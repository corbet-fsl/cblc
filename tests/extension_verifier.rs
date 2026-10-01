//! Real process adapter configuration and refusal paths; no accepting verifier.

use cblc::{
    Error,
    accounting::AccountProofScope,
    extensions::{
        EXTENSION_PROOF_BYTES, ExtensionPolicy, ExtensionStatement, ExtensionVerifier, Inbox,
        PublicRecord, RecordContext, RecordUse,
    },
    verification::ProcessExtensionVerifier,
};
use cvfy::ProcessVerifierConfig;
use std::time::Duration;

fn config() -> ProcessVerifierConfig {
    ProcessVerifierConfig {
        node: "/unavailable/node".into(),
        script: "/unavailable/verifier.mjs".into(),
        artifact_config: "/unavailable/config.json".into(),
        scope: AccountProofScope {
            circuit_digest: [71; 32],
            verifying_key_digest: [72; 32],
        },
        timeout: Duration::from_secs(1),
        maximum_parallel: 1,
        max_proof_bytes: EXTENSION_PROOF_BYTES,
        node_heap_megabytes: 64,
    }
}

#[test]
fn different_artifacts_and_invalid_independent_pools_refuse_construction() {
    let good = config();
    let mut too_small = good.clone();
    too_small.max_proof_bytes -= 1;
    assert!(matches!(
        ProcessExtensionVerifier::new(too_small, good.clone()),
        Err(Error::InvalidInput)
    ));
    for anonymous in [
        ProcessVerifierConfig {
            scope: AccountProofScope {
                circuit_digest: [73; 32],
                verifying_key_digest: [72; 32],
            },
            ..good.clone()
        },
        ProcessVerifierConfig {
            script: "/unavailable/other.mjs".into(),
            ..good.clone()
        },
        ProcessVerifierConfig {
            artifact_config: "/unavailable/other.json".into(),
            ..good.clone()
        },
    ] {
        assert!(matches!(
            ProcessExtensionVerifier::new(good.clone(), anonymous),
            Err(Error::PolicyMismatch)
        ));
    }
    let invalid = ProcessVerifierConfig {
        node: "relative-node".into(),
        ..good.clone()
    };
    assert!(matches!(
        ProcessExtensionVerifier::new(invalid.clone(), good.clone()),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        ProcessExtensionVerifier::new(good, invalid),
        Err(Error::InvalidInput)
    ));
}

#[test]
fn missing_worker_refuses_both_pools_and_releases_capacity() {
    let config = config();
    let expected_scope = config.scope.clone();
    let verifier = ProcessExtensionVerifier::new(config.clone(), config).unwrap();
    assert_eq!(verifier.scope(), expected_scope);
    let statement = ExtensionStatement::Record {
        policy: ExtensionPolicy {
            revision: 1,
            public_record_quorum: 5,
            change_token_cost: 1,
            deposit_delay_seconds: 10,
            minimum_deposit_batch: 2,
        },
        record: PublicRecord {
            context: RecordContext {
                purpose: RecordUse::FirstContact,
                challenge: [1; 32],
                expires_at: 200,
            },
            community: [2; 32],
            owner: [3; 32],
            version: 0,
            state: [4; 32],
            inbox: Inbox::default(),
            shares: None,
        },
    };
    for _ in 0..2 {
        assert_eq!(
            verifier.verify(&statement, &[1]),
            Err(Error::CryptoProvider)
        );
        assert_eq!(
            verifier.verify_anonymous(&statement, &[1]),
            Err(Error::CryptoProvider)
        );
    }
}

#[test]
fn extension_policy_requires_every_explicit_positive_economic_bound() {
    let policy = ExtensionPolicy {
        revision: 1,
        public_record_quorum: 5,
        change_token_cost: 1,
        deposit_delay_seconds: 10,
        minimum_deposit_batch: 2,
    };
    policy.validate().unwrap();
    for variant in 0..9 {
        let mut changed = policy.clone();
        match variant {
            0 => changed.revision = 0,
            1 => changed.revision = czkp::MAX_INTEGER + 1,
            2 => changed.public_record_quorum = 0,
            3 => changed.change_token_cost = 0,
            4 => changed.deposit_delay_seconds = 0,
            5 => changed.deposit_delay_seconds = czkp::MAX_INTEGER + 1,
            6 => changed.minimum_deposit_batch = 0,
            7 => changed.minimum_deposit_batch = 1,
            _ => changed.minimum_deposit_batch = 65,
        }
        assert_eq!(changed.validate(), Err(Error::InvalidInput));
    }
}
