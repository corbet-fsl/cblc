//! Actual maintained proof/issuer and recipient service scenarios.
use super::*;

/// Test community identity (founding fingerprint) the certificates bind.
const IDENTITY: [u8; 32] = [5; 32];

#[test]
fn extended_service_checks_the_configured_issuer_before_any_acceptance_and_recovers_exact_retry() {
    use cblc::{
        extensions::*,
        verification::{ExtensionLimits, NativeExtensionVerifier},
    };
    use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
    use serde_json::Value;
    use std::{num::NonZeroUsize, time::Duration};

    // Actual maintained holder trace and authenticated native artifacts. Missing
    // original generation is a fixture failure, never a skip or accepted stub.
    let directory = common::native::extension_directory();
    let trace: Vec<Value> =
        serde_json::from_slice(&std::fs::read(directory.join("public-trace.json")).unwrap())
            .unwrap();
    let find = |operation: &str| {
        trace
            .iter()
            .find(|entry| entry["response"]["ok"] == true && entry["request"]["op"] == operation)
            .unwrap()["request"]
            .clone()
    };
    let init = find("init");
    let applied = find("apply");
    assert_eq!(applied["member"], 7);
    let statement: AccountStatement = serde_json::from_value(applied["statement"].clone()).unwrap();
    assert!(statement.genesis);
    let now = statement.now;
    let artifacts = common::native::extension(&directory);
    let scope = artifacts.scope();
    assert_eq!(
        scope,
        serde_json::from_value::<AccountProofScope>(init["scope"].clone()).unwrap()
    );
    let options = common::native::options(1024 * 1024);
    let verifier = NativeExtensionVerifier::new(options.clone(), options, artifacts).unwrap();
    let f = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("service-extensions.db");
    let mut ledger = common::host_storage::open(
        &database,
        f.trust.clone(),
        AccountLedgerPolicy {
            account: serde_json::from_value(init["policy"].clone()).unwrap(),
            max_authorization_seconds: 100,
            max_proof_bytes: EXTENSION_PROOF_BYTES,
            checkpoint_period_seconds: 1000,
        },
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
    .with_extensions(
        serde_json::from_value(init["extension"].clone()).unwrap(),
        verifier,
        ExtensionLimits {
            global_burst: 1000,
            subject_burst: 500,
            replenish: Duration::from_secs(1),
            maximum_keys: NonZeroUsize::new(32).unwrap(),
        },
        ExtensionActivation {
            account: serde_json::from_value(init["activation"]["account"].clone()).unwrap(),
            proof: HEXLOWER
                .decode(init["activation"]["proof"].as_str().unwrap().as_bytes())
                .unwrap(),
        },
    )
    .unwrap();
    ledger
        .admit_checkpoint(0, statement.enrollment_root)
        .unwrap();
    let mut request = AccountRequest {
        issued_at: now,
        expires_at: statement.valid_until,
        statement,
        request_id: [83; 32],
        proof_scope: scope,
        chat_public_key: B64.encode(&f.device.verifying_key().to_bytes()),
        proof: HEXLOWER
            .decode(applied["proof"].as_str().unwrap().as_bytes())
            .unwrap(),
        signature: String::new(),
    };
    request.signature = B64.encode(
        &f.device
            .sign(&account_request_bytes(&request).unwrap())
            .to_bytes(),
    );
    let operation = AccountServiceRequest::ApplyExtended {
        grant: f.grant(7, &f.device),
        authorization: f.authorize(7, &f.device),
        request: Box::new(request.clone()),
        update: serde_json::from_value(applied["update"].clone()).unwrap(),
    };
    let stored = inspection::Connection::open(&database).unwrap();
    let before = stored.snapshot();
    let mut missing = AccountService::new(ledger, || now, 16 * 1024 * 1024).unwrap();
    assert!(matches!(
        missing.handle_for_member_authorized(&[7; 48], operation.clone(), crate::authority()),
        Err(Error::UnsupportedCapability)
    ));
    assert_eq!(stored.snapshot(), before);
    // The configured issuer becomes the open period of the recorded ring and binds the
    // community identity; configuring it writes the ring, nothing else.
    let issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    let issuer_key = issuer.public_key();
    let mut correct = AccountService::new(missing.into_ledger(), || now, 16 * 1024 * 1024)
        .unwrap()
        .with_extension_issuer(issuer, IDENTITY)
        .unwrap();
    let ring = vec![czkp::issuer_keys::CertificateKeyPeriod {
        public_key: issuer_key.to_vec(),
        valid_from: now,
        valid_until: None,
    }];
    let before = stored.snapshot();
    // A removed device (valid grant and authorization, absent from the lineage) is refused.
    assert!(matches!(
        correct.handle_for_member_authorized(
            &[7; 48],
            operation.clone(),
            crate::removed_authority()
        ),
        Err(Error::Admission)
    ));
    assert_eq!(stored.snapshot(), before);
    assert!(matches!(
        correct.handle_for_member_authorized(&[8; 48], operation.clone(), crate::authority()),
        Err(Error::Admission)
    ));
    assert_eq!(stored.snapshot(), before);
    let accepted = correct
        .handle_for_member_authorized(&[7; 48], operation.clone(), crate::authority())
        .unwrap();
    let AccountServiceResponse::ApplyExtended {
        acceptance,
        certificate,
        ancestry,
        join_publication,
    } = &accepted
    else {
        panic!("actual extended service response");
    };
    assert!(ancestry.is_none());
    // The ledger has no community signing key: the operator's account path attaches
    // the publication, never the ledger answer.
    assert!(join_publication.is_none());
    assert_eq!(acceptance.statement, request.statement);
    verify_account_acceptance(
        acceptance,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    certificate.verify(acceptance, &IDENTITY, &ring).unwrap();
    // Bound to the identity: the same certificate fails for another community.
    assert!(certificate.verify(acceptance, &[6; 32], &ring).is_err());
    let committed = stored.snapshot();
    assert_ne!(committed, before);
    let retried = correct
        .handle_for_member_authorized(&[7; 48], operation, crate::authority())
        .unwrap();
    assert_eq!(
        serde_json::to_value(retried).unwrap(),
        serde_json::to_value(accepted).unwrap()
    );
    assert_eq!(stored.snapshot(), committed);
    // The actual original three-circuit group has no R2 key. Scheduling through
    // the service cannot manufacture a publication or consume its state.
    assert!(matches!(
        correct.publish_record_epoch(1, 100),
        Err(Error::UnsupportedCapability)
    ));
    assert_eq!(stored.snapshot(), committed);
    // The identity is fixed at the first configuration; another one is refused.
    assert!(matches!(
        AccountService::new(correct.into_ledger(), || now, 16 * 1024 * 1024)
            .unwrap()
            .with_extension_issuer(
                cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap(),
                [6; 32]
            ),
        Err(Error::PolicyMismatch)
    ));
}

#[test]
fn service_registers_only_the_admitted_accounts_original_signed_recipient() {
    use cblc::accounting_ledger::record_epoch::{RecipientRequest, recipient_bytes};
    use data_encoding::BASE64URL_NOPAD as B64;
    use hpke::{Kem as _, Serializable};
    type Kem = hpke::kem::X25519HkdfSha256;
    let public = |seed| -> [u8; 32] {
        Kem::derive_keypair(&[seed; 32])
            .1
            .to_bytes()
            .as_slice()
            .try_into()
            .unwrap()
    };
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("service-recipient.db");
    let now = Arc::new(AtomicU64::new(120));
    let observed = now.clone();
    let mut service = AccountService::new(
        open(&database, &f, RealVerifier::default()),
        move || observed.load(Ordering::SeqCst),
        1024 * 1024,
    )
    .unwrap();
    let accepted_request = genesis(&f);
    service
        .publish_verified_checkpoint(0, accepted_request.statement.enrollment_root)
        .unwrap();
    let mut request = RecipientRequest {
        community: accepted_request.statement.community,
        owner: accepted_request.statement.owner,
        recipient_key: public(41),
        chat_public_key: B64.encode(&f.device.verifying_key().to_bytes()),
        lineage_epoch: 0,
        issued_at: 120,
        expires_at: 220,
        signature: String::new(),
    };
    let resign = |request: &mut RecipientRequest, device: &SigningKey| {
        request.signature = B64.encode(&device.sign(&recipient_bytes(request).unwrap()).to_bytes());
    };
    resign(&mut request, &f.device);
    let operation = |request: RecipientRequest| AccountServiceRequest::RegisterRecordRecipient {
        grant: f.grant(7, &f.device),
        authorization: f.authorize(7, &f.device),
        request,
    };
    let stored = inspection::Connection::open(&database).unwrap();
    let before = stored.snapshot();
    assert!(matches!(
        service.handle_for_member_authorized(
            &[7; 48],
            operation(request.clone()),
            crate::authority()
        ),
        Err(Error::Admission)
    ));
    assert_eq!(stored.snapshot(), before);
    service
        .handle_for_member_authorized(
            &[7; 48],
            AccountServiceRequest::Apply {
                grant: f.grant(7, &f.device),
                authorization: f.authorize(7, &f.device),
                request: Box::new(accepted_request),
            },
            crate::authority(),
        )
        .unwrap();
    let accepted = stored.snapshot();
    assert!(matches!(
        service.handle_for_member_authorized(
            &[8; 48],
            operation(request.clone()),
            crate::authority()
        ),
        Err(Error::Admission)
    ));
    assert_eq!(stored.snapshot(), accepted);
    // A removed device cannot register the recipient either.
    assert!(matches!(
        service.handle_for_member_authorized(
            &[7; 48],
            operation(request.clone()),
            crate::removed_authority()
        ),
        Err(Error::Admission)
    ));
    assert_eq!(stored.snapshot(), accepted);
    let mut wrong = request.clone();
    resign(&mut wrong, &SigningKey::from_bytes(&[43; 32]));
    assert!(matches!(
        service.handle_for_member_authorized(&[7; 48], operation(wrong), crate::authority()),
        Err(Error::Signature)
    ));
    assert_eq!(stored.snapshot(), accepted);
    let registered = service
        .handle_for_member_authorized(&[7; 48], operation(request.clone()), crate::authority())
        .unwrap();
    let AccountServiceResponse::RecordRecipient { recipient_key } = registered else {
        panic!("actual durable recipient response");
    };
    assert_eq!(recipient_key, request.recipient_key);
    let committed = stored.snapshot();
    assert_ne!(committed, accepted);
    drop(service);
    let observed = now.clone();
    let mut service = AccountService::new(
        open(&database, &f, RealVerifier::default()),
        move || observed.load(Ordering::SeqCst),
        1024 * 1024,
    )
    .unwrap();
    let retry = service
        .handle_for_member_authorized(&[7; 48], operation(request.clone()), crate::authority())
        .unwrap();
    assert!(
        matches!(retry, AccountServiceResponse::RecordRecipient { recipient_key } if recipient_key == request.recipient_key)
    );
    assert_eq!(stored.snapshot(), committed);
    let mut changed = request.clone();
    changed.recipient_key = public(42);
    resign(&mut changed, &f.device);
    assert!(matches!(
        service.handle_for_member_authorized(&[7; 48], operation(changed), crate::authority()),
        Err(Error::Replay)
    ));
    assert_eq!(stored.snapshot(), committed);
    now.store(request.expires_at, Ordering::SeqCst);
    assert!(matches!(
        service.handle_for_member_authorized(&[7; 48], operation(request), crate::authority()),
        Err(Error::Expired)
    ));
    assert_eq!(stored.snapshot(), committed);
}
