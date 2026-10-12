//! Configuration/hash refusal vectors, never a native proof acceptance fixture.
use super::*;
use crate::{
    accounting::AccountProofScope,
    accounting::AccountStatement,
    accounting_ledger::{AccountLedgerPolicy, tuning::config_bytes},
    admission::AdmissionTrust,
};

fn fixture() -> (Vec<u8>, ExtensionActivation, ArtifactBinding) {
    let policy = AccountLedgerPolicy {
        account: crate::accounting::AccountPolicy {
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
        max_proof_bytes: crate::extensions::EXTENSION_PROOF_BYTES,
        checkpoint_period_seconds: 1000,
    };
    let trust = AdmissionTrust {
        community_id: "community-example".into(),
        policy_digest: data_encoding::BASE64URL_NOPAD.encode(&[3; 32]),
        policy_keys: csgn::Signer::new(
            "community-example",
            csgn::SecretKey::from_seed(&mut [1; 32]),
            0,
            100_000,
        )
        .unwrap()
        .key_ring()
        .clone(),
    };
    let scope = AccountProofScope {
        circuit_digest: [1; 32],
        verifying_key_digest: [2; 32],
    };
    let config = config_bytes(&trust, &policy, &scope, [4; 32], 0).unwrap();
    let community = Sha256::digest(trust.community_id.as_bytes()).into();
    let mut field = [0; 32];
    field[31] = 1;
    let activation = ExtensionActivation {
        account: AccountStatement {
            protocol_version: 2,
            community,
            owner: Sha256::digest([7; 48]).into(),
            policy_digest: policy.account.digest(&community).unwrap(),
            enrollment_root: field,
            now: 100,
            valid_until: policy.account.proof_valid_until(100).unwrap(),
            genesis: true,
            previous_version: 0,
            next_version: 0,
            previous_state: [0; 32],
            next_state: field,
            settlement_marker: [0; 32],
            policy: policy.account,
        },
        // Only hash framing is tested here; actual native tests supply proofs.
        proof: vec![1; 32],
    };
    (
        config,
        activation,
        ArtifactBinding {
            manifest_sha256: [5; 32],
            certificate_key: [6; 64],
        },
    )
}

#[test]
fn unchanged_activation_anchor_allows_only_original_waiting_successor() {
    let (config, activation, binding) = fixture();
    let anchor = ActivationAnchor::new(&config, &activation, &binding).unwrap();
    anchor.check(&config, &activation, &binding).unwrap();
    let mut tuned: StoredConfig = serde_json::from_slice(&config).unwrap();
    tuned.policy.account.abandon_after = 120;
    assert!(
        anchor
            .check(&serde_json::to_vec(&tuned).unwrap(), &activation, &binding)
            .is_err()
    );
    tuned.tuning_revision = 1;
    anchor
        .check(&serde_json::to_vec(&tuned).unwrap(), &activation, &binding)
        .unwrap();
    tuned.policy.account.maximum_available += 1;
    assert!(
        anchor
            .check(&serde_json::to_vec(&tuned).unwrap(), &activation, &binding)
            .is_err()
    );
    let mut edited = activation;
    edited.account.policy.abandon_after = 120;
    edited.account.policy_digest = edited
        .account
        .policy
        .digest(&edited.account.community)
        .unwrap();
    assert!(anchor.check(&config, &edited, &binding).is_err());
}

#[test]
fn exact_activation_statement_proof_and_artifact_commitments_cannot_be_substituted() {
    let (config, activation, binding) = fixture();
    let anchor = ActivationAnchor::new(&config, &activation, &binding).unwrap();
    for case in 0..6 {
        let mut changed = anchor.clone();
        match case {
            0 => changed.format.push('x'),
            1 => changed.original_config.push(0),
            2 => changed.statement_sha256[0] ^= 1,
            3 => changed.proof_sha256[0] ^= 1,
            4 => changed.manifest_sha256[0] ^= 1,
            _ => changed.certificate_key[0] ^= 1,
        }
        assert!(changed.check(&config, &activation, &binding).is_err());
    }
    let mut changed = activation;
    changed.proof[0] ^= 1;
    assert!(anchor.check(&config, &changed, &binding).is_err());
    changed.proof[0] ^= 1;
    changed.account.owner[0] ^= 1;
    assert!(anchor.check(&config, &changed, &binding).is_err());
    let wire = serde_json::to_vec(&anchor).unwrap();
    let restored: ActivationAnchor = serde_json::from_slice(&wire).unwrap();
    restored.check(&config, &fixture().1, &binding).unwrap();
    assert!(serde_json::from_slice::<ActivationAnchor>(b"{}").is_err());
}
