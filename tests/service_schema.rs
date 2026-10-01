#![cfg(feature = "schema")]
//! Generated owner schemas describe real wire values, not proof acceptance.
mod common;

use cblc::{
    accounting::*,
    accounting_ledger::*,
    accounting_service::*,
    extensions::{Effect, ExtendedUpdate, Inbox},
    storage::MemoryStore,
};
use common::{Fixture, proofs};
use ed25519_dalek::SigningKey;
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
    let response = service.handle_for_member(&[7; 48], operation).unwrap();
    let accepted = valid(&response);
    let mut unexpected = accepted.clone();
    unexpected["override"] = true.into();
    assert!(!validator::<AccountServiceResponse>().is_valid(&unexpected));
    let mut altered = accepted;
    altered["value"]["proofScope"]["verifyingKeyDigest"] = json!("not-bytes");
    assert!(!validator::<AccountServiceResponse>().is_valid(&altered));
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
