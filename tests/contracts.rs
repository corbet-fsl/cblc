//! Original signed wire contracts, without a native service or proof verdict.
use cblc::{
    accounting::{AccountStatusRequest, account_status_bytes},
    admission::{
        AdmissionGrant, AdmissionTrust, DeviceAuthorization, admission_bytes,
        device_authorization_bytes, member_id, policy_key_id, verify_admission,
        verify_device_authorization,
    },
    contracts::{AccountServiceRequest, AccountServiceResponse, RecipientRequest, recipient_bytes},
};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

fn recipient() -> RecipientRequest {
    RecipientRequest {
        community: [1; 32],
        owner: [2; 32],
        recipient_key: [41; 32],
        chat_public_key: B64.encode(&SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes()),
        issued_at: 120,
        expires_at: 220,
        signature: String::new(),
    }
}

#[test]
fn original_recipient_transcript_and_real_device_signature_survive_the_move() {
    let key = SigningKey::from_bytes(&[2; 32]);
    let mut request = recipient();
    let original = serde_json::to_vec(&json!([
        "cblc.record-recipient.v1",
        vec![1; 32],
        vec![2; 32],
        vec![41; 32],
        "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
        120,
        220
    ]))
    .unwrap();
    assert_eq!(recipient_bytes(&request).unwrap(), original);
    request.signature = B64.encode(&key.sign(&original).to_bytes());
    czkp::signature(&request.chat_public_key, &original, &request.signature).unwrap();
    // Every signed field is still covered by the retained original transcript.
    for field in [
        "community",
        "owner",
        "recipientKey",
        "chatPublicKey",
        "issuedAt",
        "expiresAt",
    ] {
        let mut changed = serde_json::to_value(&request).unwrap();
        match field {
            "community" | "owner" | "recipientKey" => changed[field][0] = json!(9),
            "chatPublicKey" => {
                changed[field] = json!(B64.encode(&key.verifying_key().to_bytes().map(|v| v ^ 1)))
            }
            "issuedAt" => changed[field] = json!(121),
            _ => changed[field] = json!(221),
        }
        let changed: RecipientRequest = serde_json::from_value(changed).unwrap();
        assert!(
            czkp::signature(
                &request.chat_public_key,
                &recipient_bytes(&changed).unwrap(),
                &request.signature
            )
            .is_err()
        );
    }
    #[cfg(feature = "host")]
    {
        let old_path: cblc::accounting_ledger::record_epoch::RecipientRequest = request;
        assert_eq!(
            cblc::accounting_ledger::record_epoch::recipient_bytes(&old_path).unwrap(),
            original
        );
    }
}

fn status() -> AccountServiceRequest {
    let device = SigningKey::from_bytes(&[2; 32]);
    let root = SigningKey::from_bytes(&[7; 32]);
    let mut signer = csgn::Signer::new(
        "community-example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        0,
        100_000,
    )
    .unwrap();
    let trust = AdmissionTrust {
        community_id: "community-example".into(),
        policy_digest: B64.encode(&[3; 32]),
        policy_keys: signer.key_ring().clone(),
    };
    let mut grant = AdmissionGrant {
        version: 3,
        issuer_key_id: policy_key_id(&SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()),
        community_id: trust.community_id.clone(),
        member_id: member_id(&[7; 48]),
        pseudonym: HEXLOWER.encode(&[7; 48]),
        chat_public_key: B64.encode(&device.verifying_key().to_bytes()),
        policy_digest: trust.policy_digest.clone(),
        policy_epoch: 1,
        passport_policy_digest: B64.encode(&[10; 32]),
        issued_at: 100,
        expires_at: 1000,
        signature: String::new(),
    };
    grant.signature = B64.encode(
        &signer
            .sign(
                csgn::Kind::Credential,
                &admission_bytes(&grant).unwrap(),
                100,
                1000,
            )
            .unwrap(),
    );
    verify_admission(&grant, &trust, 120).unwrap();
    let mut authorization = DeviceAuthorization {
        version: 1,
        community_id: grant.community_id.clone(),
        member_id: grant.member_id.clone(),
        root_public_key: B64.encode(&root.verifying_key().to_bytes()),
        device_public_key: grant.chat_public_key.clone(),
        issued_at: 100,
        expires_at: 900,
        signature: String::new(),
    };
    authorization.signature = B64.encode(
        &root
            .sign(&device_authorization_bytes(&authorization).unwrap())
            .to_bytes(),
    );
    verify_device_authorization(&authorization, &grant, 120).unwrap();
    let mut request = AccountStatusRequest {
        community: [1; 32],
        owner: [2; 32],
        request_id: None,
        challenge: [22; 32],
        chat_public_key: grant.chat_public_key.clone(),
        issued_at: 120,
        expires_at: 180,
        signature: String::new(),
    };
    request.signature = B64.encode(
        &device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    AccountServiceRequest::Status {
        grant,
        authorization,
        request,
    }
}

#[test]
fn signed_status_wire_roundtrips_and_preserves_original_unknown_field_refusals() {
    // Genuine cryptography at the public owner boundary; no account admission.
    let request = status();
    let wire = serde_json::to_value(&request).unwrap();
    assert_eq!(wire["action"], "status");
    assert_eq!(
        serde_json::to_value(
            serde_json::from_value::<AccountServiceRequest>(wire.clone()).unwrap()
        )
        .unwrap(),
        wire
    );
    for bad in [
        {
            let mut v = wire.clone();
            v["now"] = json!(120);
            v
        },
        {
            let mut v = wire.clone();
            v["request"]["override"] = json!(true);
            v
        },
        {
            let mut v = wire.clone();
            v["action"] = json!("publishRecordEpoch");
            v
        },
    ] {
        assert!(serde_json::from_value::<AccountServiceRequest>(bad).is_err());
    }
    #[cfg(feature = "host")]
    {
        let old_path: cblc::accounting_service::AccountServiceRequest = request;
        assert_eq!(serde_json::to_value(old_path).unwrap(), wire);
    }
}

#[test]
fn original_record_recipient_response_keeps_its_existing_snake_case_field() {
    let original = json!({"action":"recordRecipient", "value":{"recipient_key":vec![41;32]}});
    let decoded: AccountServiceResponse = serde_json::from_value(original.clone()).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), original);
    for bad in [
        json!({"action":"recordRecipient", "value":{"recipientKey":vec![41;32]}}),
        json!({"action":"recordRecipient", "value":{"recipient_key":[1,2,3]}}),
        json!({"action":"recordRecipient", "value":{"recipient_key":vec![41;32],"override":true}}),
    ] {
        assert!(serde_json::from_value::<AccountServiceResponse>(bad).is_err());
    }
    #[cfg(feature = "host")]
    {
        let old_path: cblc::accounting_service::AccountServiceResponse = decoded;
        assert_eq!(serde_json::to_value(old_path).unwrap(), original);
    }
}

#[cfg(feature = "schema")]
#[test]
fn portable_owner_schemas_preserve_all_original_nested_constraints() {
    fn schema<T: schemars::JsonSchema + utoipa::ToSchema>() -> Value {
        let original = schemars::generate::SchemaSettings::draft2020_12()
            .with(|s| {
                s.meta_schema = None;
                s.inline_subschemas = true;
            })
            .with_transform(schemars::transform::ReplaceConstValue::default())
            .with_transform(schemars::transform::ReplaceUnevaluatedProperties::default())
            .into_generator()
            .into_root_schema_for::<T>();
        let wire = serde_json::to_value(T::schema()).unwrap();
        assert_eq!(wire, serde_json::to_value(original).unwrap());
        wire
    }
    let validator = jsonschema::validator_for(&schema::<AccountServiceRequest>()).unwrap();
    let valid = serde_json::to_value(status()).unwrap();
    assert!(validator.is_valid(&valid));
    let mut unknown = valid.clone();
    unknown["request"]["override"] = json!(true);
    assert!(!validator.is_valid(&unknown));
    let mut malformed = valid;
    malformed["grant"]["policyEpoch"] = Value::Null;
    assert!(!validator.is_valid(&malformed));
    let response = jsonschema::validator_for(&schema::<AccountServiceResponse>()).unwrap();
    assert!(
        response
            .is_valid(&json!({"action":"recordRecipient", "value":{"recipient_key":vec![41;32]}}))
    );
    assert!(!response.is_valid(
        &json!({"action":"recordRecipient", "value":{"recipient_key":vec![41;32],"override":true}})
    ));
}
