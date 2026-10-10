//! Service boundary tests use actual maintained holder proofs and the shipped verifier.
mod common;
#[path = "support/inspect.rs"]
mod inspection;
use cblc::{Error, accounting::*, accounting_ledger::*, accounting_service::*};
use common::{
    Fixture,
    proofs::{self, RealVerifier},
};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
fn policy() -> AccountLedgerPolicy {
    // Test values only. Library consumers must choose their own complete policy.
    AccountLedgerPolicy {
        account: AccountPolicy {
            initial_credit: 3,
            maximum_available: 4,
            outgoing_reservation: 1,
            incoming_reservation: 1,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 2000,
            newcomer_period: 100,
            rate_window: 1000,
            newcomer_admissions: 2,
            maximum_admissions: 4,
            refill_period: 100,
            refill_units: 1,
            abandon_after: 1000,
        },
        max_authorization_seconds: 100,
        max_proof_bytes: 1024 * 1024,
        checkpoint_period_seconds: 1000,
    }
}
fn open<V: AccountProofVerifier>(path: &Path, fixture: &Fixture, verifier: V) -> AccountLedger<V> {
    common::host_storage::open(
        path,
        fixture.trust.clone(),
        policy(),
        verifier,
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
}
fn genesis(fixture: &Fixture) -> AccountRequest {
    proofs::request(0, 10, fixture)
}

#[test]
fn member_wire_cannot_supply_time_or_admin_operations() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut service = AccountService::new(
        open(&dir.path().join("accounts"), &f, RealVerifier::default()),
        || 110,
        100_000,
    )
    .unwrap();
    service
        .publish_verified_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    for body in [
        serde_json::json!({"action":"tuneWaitingPeriod","seconds":1000}),
        serde_json::json!({"action":"publishCheckpoint","root":proofs::record(0).statement.enrollment_root}),
        serde_json::json!({"action":"apply","grant":f.grant(7,&f.device),"authorization":f.authorize(7,&f.device),"request":genesis(&f),"now":110}),
    ] {
        assert_eq!(
            service.handle_json(&serde_json::to_vec(&body).unwrap()),
            Err(Error::InvalidInput)
        );
    }
    assert_eq!(service.handle_json(&vec![0; 100_001]), Err(Error::Capacity));
    let good = serde_json::json!({"action":"apply","grant":f.grant(7,&f.device),"authorization":f.authorize(7,&f.device),"request":genesis(&f)});
    assert!(good["grant"].get("issuerKeyId").is_some());
    let response = service
        .handle_json(&serde_json::to_vec(&good).unwrap())
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response).unwrap()["action"],
        "apply"
    );
    let (configured, tuning) = service.policy().unwrap();
    assert_eq!(configured, policy().account);
    assert_eq!(tuning.revision, 0);
    let original = genesis(&f);
    let mut request = AccountStatusRequest {
        community: original.statement.community,
        owner: original.statement.owner,
        request_id: None,
        challenge: [37; 32],
        chat_public_key: original.chat_public_key,
        issued_at: 110,
        expires_at: 170,
        signature: String::new(),
    };
    request.signature = data_encoding::BASE64URL_NOPAD.encode(
        &f.device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    let observed = service
        .handle_for_member(
            &[7; 48],
            AccountServiceRequest::Status {
                grant: f.grant(7, &f.device),
                authorization: f.authorize(7, &f.device),
                request: request.clone(),
            },
        )
        .unwrap();
    let AccountServiceResponse::Status(observed) = observed else {
        panic!("status response")
    };
    verify_account_status_response(
        &observed,
        &request,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(observed.acceptance.unwrap().request_id, original.request_id);
}

#[test]
fn server_clock_overrules_member_time_and_retry_recovers_after_tuning() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let clock = Arc::new(AtomicU64::new(181));
    let observed = clock.clone();
    let mut service = AccountService::new(
        open(&dir.path().join("accounts"), &f, RealVerifier::default()),
        move || observed.load(Ordering::SeqCst),
        100_000,
    )
    .unwrap();
    service
        .publish_verified_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let request = AccountServiceRequest::Apply {
        grant: f.grant(7, &f.device),
        authorization: f.authorize(7, &f.device),
        request: Box::new(genesis(&f)),
    };
    assert!(matches!(
        service.handle(request.clone()),
        Err(Error::Expired)
    ));
    clock.store(110, Ordering::SeqCst);
    assert!(matches!(
        service.handle(request.clone()),
        Err(Error::ClockRollback)
    ));
    // This independent scenario starts with a valid clock. Reloading the first
    // service must never erase its observation of the later expired request.
    let observed = clock.clone();
    let mut service = AccountService::new(
        open(
            &dir.path().join("retry-accounts"),
            &f,
            RealVerifier::default(),
        ),
        move || observed.load(Ordering::SeqCst),
        100_000,
    )
    .unwrap();
    service
        .publish_verified_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let accepted = service.handle(request.clone()).unwrap();
    assert!(matches!(accepted, AccountServiceResponse::Apply(_)));
    let tune = service.tune_waiting_period(0, 1100).unwrap();
    assert_eq!(tune.seconds, 1100);
    assert!(matches!(
        service.tune_waiting_period(0, 1200),
        Err(Error::PolicyMismatch)
    ));
    clock.store(181, Ordering::SeqCst);
    let retry = service.handle(request).unwrap();
    assert_eq!(
        serde_json::to_value(accepted).unwrap(),
        serde_json::to_value(retry).unwrap()
    );
}

#[test]
fn invalid_authority_cannot_register_an_account() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut service = AccountService::new(
        open(&dir.path().join("accounts"), &f, RealVerifier::default()),
        || 110,
        100_000,
    )
    .unwrap();
    service
        .publish_verified_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let bad = AccountServiceRequest::Apply {
        grant: f.grant(8, &f.device),
        authorization: f.authorize(8, &f.device),
        request: Box::new(genesis(&f)),
    };
    assert!(matches!(service.handle(bad), Err(Error::Admission)));
    service
        .handle(AccountServiceRequest::Apply {
            grant: f.grant(7, &f.device),
            authorization: f.authorize(7, &f.device),
            request: Box::new(genesis(&f)),
        })
        .unwrap();
}

#[test]
fn actual_js_client_request_is_accepted_by_rust_and_js_checks_the_signed_rust_reply() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    fn javascript(mode: &str, input: serde_json::Value) -> Vec<u8> {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/holder/test/rust-client-interop.mjs");
        let mut child = Command::new("node")
            .arg(script)
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        output.stdout
    }
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let request = genesis(&f);
    let operator = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let body = javascript(
        "prepare",
        serde_json::json!({"operatorPublicKey":operator,"grant":f.grant(7,&f.device),
        "authorization":f.authorize(7,&f.device),"prepare":{"record":{"statement":request.statement,
        "proof":data_encoding::HEXLOWER.encode(&request.proof),"proofScope":request.proof_scope},
        "chatPublicKey":request.chat_public_key,"expiresAt":request.expires_at,"requestId":request.request_id}}),
    );
    let mut service = AccountService::new(
        open(&dir.path().join("accounts"), &f, RealVerifier::default()),
        || 110,
        100_000,
    )
    .unwrap();
    service
        .publish_verified_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let response: serde_json::Value =
        serde_json::from_slice(&service.handle_json(&body).unwrap()).unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let verified = javascript(
        "verify",
        serde_json::json!({"acceptance":response["value"],"request":envelope["request"],"operatorPublicKey":operator}),
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified).unwrap()["ok"],
        true
    );
}

#[test]
fn native_verifier_checks_domain_input_and_refuses_unavailable_backend_without_retaining_capacity()
{
    // Native process framing/timeout adversaries live in cvfy. This adapter test
    // retains the domain checks and only observes genuine backend refusal.
    let directory = std::path::PathBuf::from(std::env::var_os("CBLC_PROOF_DIRECTORY").unwrap());
    let artifacts = common::native::account(&directory);
    assert_eq!(artifacts.scope(), proofs::record(0).proof_scope);
    let mut options = common::native::options(1024 * 1024);
    options.executable = "/unavailable/czkp-bb-worker".into();
    let verifier = NativeAccountVerifier::new(options, artifacts).unwrap();
    let statement = genesis(&Fixture::new()).statement;
    for _ in 0..2 {
        assert_eq!(
            verifier.verify(&statement, &[1; 32]),
            Err(Error::CryptoProvider)
        );
    }
    let mut malformed = statement.clone();
    malformed.policy_digest[0] ^= 1;
    assert_eq!(
        verifier.verify(&malformed, &[1; 32]),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        verifier.verify(&statement, &vec![0; 1024 * 1024 + 1]),
        Err(Error::InvalidInput)
    );
}

#[test]
fn service_capacity_rejects_invalid_bounds_and_preserves_host_policy() {
    let f = Fixture::new();
    for limit in [0, 16 * 1024 * 1024 + 1, 1, 16 * 1024 * 1024] {
        let dir = tempfile::tempdir().unwrap();
        let ledger = open(&dir.path().join("accounts"), &f, RealVerifier::default());
        let result = AccountService::new(ledger, || 120, limit);
        if limit == 0 || limit > 16 * 1024 * 1024 {
            assert!(matches!(result, Err(Error::InvalidInput)));
        } else {
            let service = result.unwrap();
            assert_eq!(service.max_request_bytes(), limit);
            assert_eq!(service.into_ledger().account_policy(), &policy().account);
        }
    }
}

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
        missing.handle_for_member(&[7; 48], operation.clone()),
        Err(Error::UnsupportedCapability)
    ));
    assert_eq!(stored.snapshot(), before);
    let mut wrong = AccountService::new(missing.into_ledger(), || now, 16 * 1024 * 1024)
        .unwrap()
        .with_extension_issuer(cssr::certificate::CertificateIssuer::new(&[4; 32]).unwrap());
    assert!(matches!(
        wrong.handle_for_member(&[7; 48], operation.clone()),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(stored.snapshot(), before);
    let issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    let issuer_key = issuer.public_key();
    let mut correct = AccountService::new(wrong.into_ledger(), || now, 16 * 1024 * 1024)
        .unwrap()
        .with_extension_issuer(issuer);
    assert!(matches!(
        correct.handle_for_member(&[8; 48], operation.clone()),
        Err(Error::Admission)
    ));
    assert_eq!(stored.snapshot(), before);
    let accepted = correct
        .handle_for_member(&[7; 48], operation.clone())
        .unwrap();
    let AccountServiceResponse::ApplyExtended {
        acceptance,
        certificate,
        ancestry,
    } = &accepted
    else {
        panic!("actual extended service response");
    };
    assert!(ancestry.is_none());
    assert_eq!(acceptance.statement, request.statement);
    verify_account_acceptance(
        acceptance,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    cssr::certificate::verify(
        &issuer_key,
        &cssr::certificate::AcceptedState {
            community: request.statement.community,
            owner: request.statement.owner,
            state: request.statement.next_state,
            scope: request.proof_scope.circuit_digest,
            version: request.statement.next_version,
            accepted_at: acceptance.accepted_at,
        },
        certificate.signature.as_slice().try_into().unwrap(),
    )
    .unwrap();
    let committed = stored.snapshot();
    assert_ne!(committed, before);
    let retried = correct.handle_for_member(&[7; 48], operation).unwrap();
    assert_eq!(
        serde_json::to_value(retried).unwrap(),
        serde_json::to_value(accepted).unwrap()
    );
    assert_eq!(stored.snapshot(), committed);
}
