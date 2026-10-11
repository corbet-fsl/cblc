//! Canonical configuration comparison only, not proof/acceptance evidence.
use super::*;

fn config() -> StoredConfig {
    StoredConfig {
        format: "cblc.account.database.v5".into(),
        community_id: "community.example".into(),
        admission_policy_digest: "opaque-policy-digest".into(),
        policy_keys: vec![1, 2, 3],
        proof_scope: AccountProofScope {
            circuit_digest: [1; 32],
            verifying_key_digest: [2; 32],
        },
        operator_key: [3; 32],
        tuning_revision: 0,
        policy: AccountLedgerPolicy {
            account: AccountPolicy {
                initial_credit: 3,
                maximum_available: 3,
                outgoing_reservation: 1,
                incoming_reservation: 1,
                policy_revision: 1,
                policy_valid_from: 1,
                policy_valid_until: 2000,
                newcomer_period: 100,
                rate_window: 10,
                newcomer_admissions: 8,
                maximum_admissions: 8,
                refill_period: 10,
                refill_units: 1,
                abandon_after: 100,
            },
            max_authorization_seconds: 100,
            max_proof_bytes: 4 * 1024 * 1024,
            checkpoint_period_seconds: 1000,
        },
    }
}

#[test]
fn only_a_newer_valid_waiting_revision_preserves_epoch_authority() {
    let bytes = serde_json::to_vec(&config()).unwrap();
    check_epoch_config(&bytes, &bytes).unwrap();
    let mut tuned = config();
    tuned.policy.account.abandon_after = 120;
    assert!(check_epoch_config(&bytes, &serde_json::to_vec(&tuned).unwrap()).is_err());
    tuned.tuning_revision = 1;
    let current = serde_json::to_vec(&tuned).unwrap();
    check_epoch_config(&bytes, &current).unwrap();
    assert!(check_epoch_config(&current, &bytes).is_err());
    tuned.tuning_revision = MAX_INTEGER;
    check_epoch_config(&bytes, &serde_json::to_vec(&tuned).unwrap()).unwrap();
    tuned.tuning_revision = MAX_INTEGER + 1;
    assert!(check_epoch_config(&bytes, &serde_json::to_vec(&tuned).unwrap()).is_err());
    tuned.tuning_revision = 1;
    tuned.policy.account.abandon_after = 0;
    assert!(check_epoch_config(&bytes, &serde_json::to_vec(&tuned).unwrap()).is_err());
    assert!(check_epoch_config(b"invalid", &bytes).is_err());
    assert!(check_epoch_config(&bytes, b"invalid").is_err());
}

#[test]
fn immutable_configuration_remains_bound_even_at_a_newer_revision() {
    let bytes = serde_json::to_vec(&config()).unwrap();
    for variant in 0..12 {
        let mut changed = config();
        changed.tuning_revision = 1;
        changed.policy.account.abandon_after = 120;
        match variant {
            0 => changed.format.push('x'),
            1 => changed.community_id.push('x'),
            2 => changed.admission_policy_digest.push('x'),
            3 => changed.policy_keys.push(4),
            4 => changed.operator_key[0] ^= 1,
            5 => changed.proof_scope.circuit_digest[0] ^= 1,
            6 => changed.proof_scope.verifying_key_digest[0] ^= 1,
            7 => changed.policy.max_authorization_seconds += 1,
            8 => changed.policy.max_proof_bytes += 1,
            9 => changed.policy.checkpoint_period_seconds += 1,
            10 => changed.policy.account.initial_credit -= 1,
            _ => changed.policy.account.policy_revision += 1,
        }
        assert!(check_epoch_config(&bytes, &serde_json::to_vec(&changed).unwrap()).is_err());
    }
}

#[test]
fn legacy_detached_key_configuration_is_not_inferred_as_a_policy_ring() {
    let current = serde_json::to_vec(&config()).unwrap();
    let mut legacy = serde_json::to_value(config()).unwrap();
    legacy["format"] = "cblc.account.database.v3".into();
    let fields = legacy.as_object_mut().unwrap();
    fields.remove("policyKeys");
    fields.insert(
        "issuerPublicKey".into(),
        serde_json::to_value([4u8; 32]).unwrap(),
    );
    let legacy = serde_json::to_vec(&legacy).unwrap();
    assert_eq!(check_epoch_config(&legacy, &current), Err(Error::Storage));
    assert_eq!(check_epoch_config(&current, &legacy), Err(Error::Storage));
}
