//! Native adapter configuration and refusal paths; no accepting verifier.
// This target reuses only the artifact and proof-record subset of the fixtures.
#[allow(dead_code)]
mod common;
use cblc::{
    Error,
    artifacts::NativeVerifierOptions,
    extensions::{
        Effect, ExtendedUpdate, ExtensionPolicy, ExtensionStatement, ExtensionVerifier, Inbox,
        PublicRecord, RecordContext, RecordUse,
    },
    verification::NativeExtensionVerifier,
};
use std::time::Duration;

fn config() -> NativeVerifierOptions {
    NativeVerifierOptions {
        executable: "/unavailable/czkp-bb-worker".into(),
        timeout: Duration::from_secs(1),
        maximum_parallel: 1,
        max_proof_bytes: 1024 * 1024,
        threads: 1,
        memory_megabytes: 8192,
    }
}

#[test]
fn invalid_independent_pools_refuse_construction() {
    let artifacts = common::native::extension(&common::native::extension_directory());
    for field in 0..5 {
        let mut invalid = config();
        match field {
            0 => invalid.executable = "relative-worker".into(),
            1 => invalid.timeout = Duration::ZERO,
            2 => invalid.maximum_parallel = 0,
            3 => invalid.max_proof_bytes = 0,
            _ => invalid.threads = 0,
        }
        assert!(matches!(
            NativeExtensionVerifier::new(invalid.clone(), config(), artifacts.clone()),
            Err(Error::InvalidInput)
        ));
        assert!(matches!(
            NativeExtensionVerifier::new(config(), invalid, artifacts.clone()),
            Err(Error::InvalidInput)
        ));
    }
}

#[test]
fn missing_worker_refuses_both_pools_and_domain_confusion_without_accepting_a_proof() {
    let artifacts = common::native::extension(&common::native::extension_directory());
    let expected_scope = artifacts.scope();
    let verifier = NativeExtensionVerifier::new(config(), config(), artifacts).unwrap();
    assert_eq!(verifier.scope(), expected_scope);
    assert_eq!(
        verifier.require_record_epoch(),
        Err(Error::UnsupportedCapability)
    );
    let policy = ExtensionPolicy {
        revision: 1,
        public_record_quorum: 5,
        change_token_cost: 1,
        deposit_delay_seconds: 10,
        minimum_deposit_batch: 2,
        standing_policy_digest: [9; 32],
    };
    let record = ExtensionStatement::Record {
        policy: policy.clone(),
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
    let account = common::proofs::record(0).statement;
    let update = ExtensionStatement::Update {
        policy,
        account: Box::new(account.clone()),
        update: ExtendedUpdate {
            previous_inbox: Inbox::default(),
            inbox: Inbox::default(),
            effect: Effect::Update,
        },
    };
    let record_proof =
        serde_json::to_vec(&serde_json::json!({"version":1,"proofs":[{"proof":"01".repeat(32)}]}))
            .unwrap();
    let update_proof = serde_json::to_vec(&serde_json::json!({"version":1,"proofs":[{
        "state":account.next_state,"inbox": vec![0_u8;32],"proof":"01".repeat(32)
    }]}))
    .unwrap();
    for _ in 0..2 {
        assert_eq!(
            verifier.verify(&update, &update_proof),
            Err(Error::CryptoProvider)
        );
        assert_eq!(
            verifier.verify_anonymous(&record, &record_proof),
            Err(Error::CryptoProvider)
        );
        assert_eq!(
            verifier.verify(&record, &record_proof),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            verifier.verify_anonymous(&update, &update_proof),
            Err(Error::InvalidInput)
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
        standing_policy_digest: [9; 32],
    };
    policy.validate().unwrap();
    for variant in 0..10 {
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
            8 => changed.minimum_deposit_batch = 65,
            _ => changed.standing_policy_digest = [0; 32],
        }
        assert_eq!(changed.validate(), Err(Error::InvalidInput));
    }
}
