#![cfg(feature = "schema")]
//! Generated owner schemas describe real wire values, not proof acceptance.

use crate::common::{Fixture, proofs};
use cblc::{
    accounting::*,
    accounting_ledger::*,
    accounting_service::*,
    extensions::{Effect, ExtendedUpdate, Inbox},
    storage::MemoryStore,
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;

fn validator<T: ToSchema + schemars::JsonSchema>() -> jsonschema::Validator {
    let mut components = Vec::new();
    T::schemas(&mut components);
    let mut schema = serde_json::to_value(T::schema()).unwrap();
    // Ensure the OpenAPI projection has not silently discarded a constraint.
    // The independent maintained generator reads the actual Serde wire types.
    let original = schemars::generate::SchemaSettings::draft2020_12()
        .with(|settings| {
            settings.meta_schema = None;
            settings.inline_subschemas = true;
        })
        .with_transform(schemars::transform::ReplaceConstValue::default())
        .with_transform(schemars::transform::ReplaceUnevaluatedProperties::default())
        .into_generator()
        .into_root_schema_for::<T>();
    assert_eq!(schema, serde_json::to_value(original).unwrap());
    let schemas: serde_json::Map<String, Value> = components
        .into_iter()
        .map(|(name, value)| (name, serde_json::to_value(value).unwrap()))
        .collect();
    schema["components"] = json!({"schemas": schemas});
    jsonschema::validator_for(&schema).unwrap()
}

fn valid<T: ToSchema + Serialize + schemars::JsonSchema>(value: &T) -> Value {
    let json = serde_json::to_value(value).unwrap();
    assert!(validator::<T>().is_valid(&json));
    json
}

#[test]
fn generated_projection_preserves_every_serde_constraint() {
    validator::<AccountServiceRequest>();
    validator::<AccountServiceResponse>();
    #[cfg(feature = "publication")]
    validator::<cblc::publication::PublicVerifierMaterial>();
}

#[test]
fn requests_and_actual_issued_responses_share_the_owner_schema() {
    let f = Fixture::new();
    let request = proofs::request(0, 10, &f);
    let grant = f.grant(7, &f.device);
    let authorization = f.authorize(7, &f.device);
    let operation = AccountServiceRequest::Apply {
        grant: grant.clone(),
        authorization: authorization.clone(),
        request: Box::new(request.clone()),
    };
    let encoded = valid(&operation);
    let schema = validator::<AccountServiceRequest>();
    for pointer in ["/grant/pseudonym", "/request/proofScope/circuitDigest"] {
        let mut invalid = encoded.clone();
        *invalid.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(!schema.is_valid(&invalid));
    }
    let mut injected = encoded.clone();
    injected["now"] = 120.into();
    assert!(!schema.is_valid(&injected));
    let mut nested = encoded;
    nested["request"]["untrustedOverride"] = true.into();
    assert!(!schema.is_valid(&nested));
    let extended = valid(&AccountServiceRequest::ApplyExtended {
        grant: grant.clone(),
        authorization: authorization.clone(),
        request: Box::new(request.clone()),
        update: ExtendedUpdate {
            previous_inbox: Inbox::default(),
            inbox: Inbox::default(),
            effect: Effect::Update,
        },
    });
    let mut unknown_effect = extended;
    unknown_effect["update"]["effect"]["override"] = true.into();
    assert!(!schema.is_valid(&unknown_effect));
    let policy = AccountLedgerPolicy {
        account: request.statement.policy.clone(),
        max_authorization_seconds: 100,
        max_proof_bytes: 1024 * 1024,
        checkpoint_period_seconds: 1000,
    };
    let mut ledger = AccountLedger::with_store(
        MemoryStore::default(),
        f.trust.clone(),
        policy,
        proofs::RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    ledger
        .admit_checkpoint(0, request.statement.enrollment_root)
        .unwrap();
    let mut service = AccountService::new(ledger, || 120, 1024 * 1024).unwrap();
    let response = service
        .handle_for_member_authorized(&[7; 48], operation, self::authority())
        .unwrap();
    let accepted = valid(&response);
    let mut unexpected = accepted.clone();
    unexpected["override"] = true.into();
    assert!(!validator::<AccountServiceResponse>().is_valid(&unexpected));
    let mut altered = accepted;
    altered["value"]["proofScope"]["verifyingKeyDigest"] = json!("not-bytes");
    assert!(!validator::<AccountServiceResponse>().is_valid(&altered));
    // The schema carries the original admitted account's actual device-signed
    // recipient operation; shape validation alone is not registration authority.
    use hpke::{Kem as _, Serializable};
    let recipient_key: [u8; 32] = hpke::kem::X25519HkdfSha256::derive_keypair(&[77; 32])
        .1
        .to_bytes()
        .as_slice()
        .try_into()
        .unwrap();
    let mut recipient = cblc::accounting_ledger::record_epoch::RecipientRequest {
        community: request.statement.community,
        owner: request.statement.owner,
        recipient_key,
        chat_public_key: request.chat_public_key.clone(),
        lineage_epoch: 0,
        issued_at: 120,
        expires_at: 220,
        signature: String::new(),
    };
    recipient.signature = data_encoding::BASE64URL_NOPAD.encode(
        &f.device
            .sign(&cblc::accounting_ledger::record_epoch::recipient_bytes(&recipient).unwrap())
            .to_bytes(),
    );
    let registration = AccountServiceRequest::RegisterRecordRecipient {
        grant: grant.clone(),
        authorization: authorization.clone(),
        request: recipient,
    };
    let encoded = valid(&registration);
    for bad in [
        {
            let mut value = encoded.clone();
            value["request"]["recipientKey"] = json!([1, 2, 3]);
            value
        },
        {
            let mut value = encoded.clone();
            value["request"]["now"] = json!(120);
            value
        },
        json!({"action":"publishRecordEpoch","policyEpoch":1,"periodSeconds":100}),
    ] {
        assert!(!schema.is_valid(&bad));
        assert!(serde_json::from_value::<AccountServiceRequest>(bad).is_err());
    }
    let registered = service
        .handle_for_member_authorized(&[7; 48], registration, self::authority())
        .unwrap();
    assert!(
        matches!(&registered, AccountServiceResponse::RecordRecipient { recipient_key: key } if *key == recipient_key)
    );
    let encoded = valid(&registered);
    let mut altered = encoded.clone();
    altered["value"]["recipient_key"] = json!([1, 2, 3]);
    assert!(!validator::<AccountServiceResponse>().is_valid(&altered));
    let mut injected = encoded;
    injected["value"]["override"] = true.into();
    assert!(!validator::<AccountServiceResponse>().is_valid(&injected));
    let status = AccountStatusRequest {
        community: request.statement.community,
        owner: request.statement.owner,
        request_id: None,
        challenge: [22; 32],
        chat_public_key: request.chat_public_key,
        issued_at: 120,
        expires_at: 180,
        signature: String::new(),
    };
    // Shape validation does not mistake this unsigned query for authority.
    valid(&AccountServiceRequest::Status {
        grant: grant.clone(),
        authorization: authorization.clone(),
        request: status.clone(),
    });
    valid(&AccountServiceRequest::Obligations {
        grant,
        authorization,
        request: status,
    });
}

/// Test authority: always current, and every device is in the lineage.
pub(crate) struct TestAuthority;
impl cblc::storage::CommitAuthority for TestAuthority {
    fn check(&self, _: u64) -> Result<(), cblc::Error> {
        Ok(())
    }
    fn boundary_crossed(&self, _: u64, _: u64) -> Result<bool, cblc::Error> {
        Ok(false)
    }
    fn lineage(&self) -> Option<&dyn cblc::current_device::CurrentLineage> {
        Some(&TestLineage)
    }
}
pub(crate) struct TestLineage;
impl cblc::current_device::CurrentLineage for TestLineage {
    fn is_current(&self, _: &[u8; 32]) -> bool {
        true
    }
}
pub(crate) fn authority() -> std::sync::Arc<dyn cblc::storage::CommitAuthority> {
    std::sync::Arc::new(TestAuthority)
}
