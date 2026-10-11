//! Genuine native activation and SQL catchup after an independently signed ring
//! advances while this same durable ledger is stopped. No proof is regenerated.
use super::*;
use cblc::accounting_ledger::{AdmissionKeyReconciliation, AdmissionKeyState};

fn rotate(signer: &mut csgn::Signer, seed: u8, now: u64, until: u64) -> Vec<u8> {
    let proof = signer
        .rotate_with_proof(csgn::SecretKey::from_seed(&mut [seed; 32]), now, until)
        .unwrap();
    signer
        .acknowledge_transition(signer.ring_revision())
        .unwrap();
    proof
}
fn target(signer: &csgn::Signer) -> AdmissionKeyState {
    AdmissionKeyState {
        revision: signer.ring_revision(),
        policy_keys: signer.key_ring().clone(),
    }
}

pub(super) fn exercise(
    fixture: &Fixture,
    settings: &AccountLedgerPolicy,
    extension: &ExtensionPolicy,
    scope: &AccountProofScope,
    directory: &Path,
    init: &Value,
) {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("admission-catchup.db");
    assert_eq!(
        common::host_storage::startup_clock_floor(&path, "community.example").unwrap(),
        0
    );
    let mut signer = csgn::Signer::new(
        "community.example",
        csgn::SecretKey::from_seed(&mut [21; 32]),
        1,
        100_000,
    )
    .unwrap();
    let mut trust = fixture.trust.clone();
    trust.policy_keys = signer.key_ring().clone();
    let mut ledger = common::host_storage::open_with_admission_keys(
        &path,
        trust.clone(),
        settings.clone(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
        target(&signer),
    )
    .unwrap()
    .with_extensions(
        extension.clone(),
        verifier(scope.clone(), directory),
        limits(),
        activation(init),
    )
    .unwrap();
    let mut stale = common::host_storage::open_with_admission_keys(
        &path,
        trust.clone(),
        settings.clone(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
        target(&signer),
    )
    .unwrap();
    let original_anchor = anchor(&path);
    let tuned = ledger
        .update_waiting_period(0, settings.account.abandon_after + 10, || 110)
        .unwrap();
    drop(ledger);
    assert_eq!(
        common::host_storage::startup_clock_floor(&path, "community.example").unwrap(),
        110
    );
    let first = rotate(&mut signer, 22, 120, 1000);
    let second = rotate(&mut signer, 23, 130, 160);
    let requested = target(&signer);
    trust.policy_keys = signer.key_ring().clone();
    let retained = inspection::Connection::open(&path).unwrap().snapshot();
    // The ordinary strict constructor cannot substitute Policy's new ring for
    // the durable old ring or manufacture acceptance at startup.
    assert!(
        common::host_storage::open_with_admission_keys(
            &path,
            trust.clone(),
            settings.clone(),
            RealVerifier::default(),
            SigningKey::from_bytes(&[9; 32]),
            requested.clone()
        )
        .is_err()
    );
    for (now, transitions, desired) in [
        (
            125,
            vec![(1, first.clone()), (2, second.clone())],
            requested.clone(),
        ),
        (
            160,
            vec![(1, first.clone()), (2, second.clone())],
            requested.clone(),
        ),
        (140, vec![(2, second.clone())], requested.clone()),
        (140, vec![(1, first.clone())], requested.clone()),
        (
            140,
            vec![(1, first.clone()), (2, second.clone())],
            AdmissionKeyState {
                revision: 2,
                policy_keys: fixture.trust.policy_keys.clone(),
            },
        ),
    ] {
        let mut desired_trust = trust.clone();
        desired_trust.policy_keys = desired.policy_keys.clone();
        assert!(
            common::host_storage::open_reconciled(
                &path,
                desired_trust,
                settings.clone(),
                RealVerifier::default(),
                SigningKey::from_bytes(&[9; 32]),
                AdmissionKeyReconciliation {
                    target: desired,
                    transitions
                },
                || now
            )
            .is_err()
        );
        assert_eq!(
            inspection::Connection::open(&path).unwrap().snapshot(),
            retained
        );
    }
    let mut ledger = common::host_storage::open_reconciled(
        &path,
        trust.clone(),
        settings.clone(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
        AdmissionKeyReconciliation {
            target: requested.clone(),
            transitions: vec![(1, first.clone()), (2, second.clone())],
        },
        || 140,
    )
    .unwrap()
    .with_extensions(
        extension.clone(),
        verifier(scope.clone(), directory),
        limits(),
        activation(init),
    )
    .unwrap();
    assert_eq!(ledger.admission_key_state().unwrap(), requested);
    assert_eq!(ledger.waiting_period().unwrap(), tuned);
    assert_eq!(anchor(&path), original_anchor);
    assert_eq!(
        common::host_storage::startup_clock_floor(&path, "community.example").unwrap(),
        140
    );
    assert!(matches!(
        stale.update_waiting_period(0, 120, || 141),
        Err(Error::PolicyMismatch)
    ));
    stale.reload_policy().unwrap();
    assert_eq!(stale.admission_key_state().unwrap(), requested);
    let retained = inspection::Connection::open(&path).unwrap().snapshot();
    let mut forked = first.clone();
    let last = forked.len() - 1;
    forked[last] ^= 1;
    assert!(
        ledger
            .reconcile_admission_keys(
                AdmissionKeyReconciliation {
                    target: requested.clone(),
                    transitions: vec![(1, forked), (2, second.clone())]
                },
                || 141
            )
            .is_err()
    );
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
    // An exact already-observed prefix remains historical after expiry. It does
    // not acquire new live authority, and an identical target never mutates it.
    assert_eq!(
        ledger
            .reconcile_admission_keys(
                AdmissionKeyReconciliation {
                    target: requested.clone(),
                    transitions: vec![(1, first.clone()), (2, second.clone())]
                },
                || 170
            )
            .unwrap(),
        requested
    );
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
    let third = rotate(&mut signer, 24, 180, 1000);
    let next = target(&signer);
    let samples = Cell::new(0);
    assert!(matches!(
        ledger.reconcile_admission_keys(
            AdmissionKeyReconciliation {
                target: next.clone(),
                transitions: vec![(1, first.clone()), (2, second.clone()), (3, third.clone())]
            },
            || {
                let sample = samples.get();
                samples.set(sample + 1);
                if sample < 4 { 180 } else { 1000 }
            }
        ),
        Err(Error::Storage)
    ));
    assert_eq!(samples.get(), 5);
    ledger.reload_policy().unwrap();
    assert_eq!(ledger.admission_key_state().unwrap(), next);
    assert_eq!(anchor(&path), original_anchor);
    drop(stale);
    drop(ledger);
    trust.policy_keys = signer.key_ring().clone();
    let mut reopened = common::host_storage::open_reconciled(
        &path,
        trust.clone(),
        settings.clone(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
        AdmissionKeyReconciliation {
            target: next,
            transitions: vec![(1, first), (2, second), (3, third)],
        },
        || 1000,
    )
    .unwrap()
    .with_extensions(
        extension.clone(),
        verifier(scope.clone(), directory),
        limits(),
        activation(init),
    )
    .unwrap();
    assert_eq!(reopened.admission_key_state().unwrap().revision, 3);
    assert_eq!(reopened.waiting_period().unwrap(), tuned);
    assert_eq!(anchor(&path), original_anchor);
    // The owner probe never supplies a missing or malformed durable floor.
    // Restore exact original bytes between cases; no startup parser lives in the host.
    let mut store = cssr::LibsqlStore::local(&path, "community.example").unwrap();
    let mut tx = store.transaction().unwrap();
    let original_floor = tx.get(b"clock").unwrap().unwrap();
    tx.rollback().unwrap();
    for changed in [
        None,
        Some(serde_json::to_vec(&u64::MAX).unwrap()),
        Some(b"invalid".to_vec()),
    ] {
        let mut tx = store.transaction().unwrap();
        match changed {
            Some(bytes) => tx.put(b"clock", &bytes).unwrap(),
            None => tx.delete(b"clock").unwrap(),
        }
        tx.commit().unwrap();
        assert!(common::host_storage::startup_clock_floor(&path, "community.example").is_err());
        let mut tx = store.transaction().unwrap();
        tx.put(b"clock", &original_floor).unwrap();
        tx.commit().unwrap();
    }
    // Deleting just the durable configuration cannot turn an existing owner
    // into a new bootstrap, even when its public transition target is genuine.
    let mut store = cssr::LibsqlStore::local(&path, "community.example").unwrap();
    let mut tx = store.transaction().unwrap();
    tx.delete(b"config").unwrap();
    tx.commit().unwrap();
    let retained = inspection::Connection::open(&path).unwrap().snapshot();
    assert!(common::host_storage::startup_clock_floor(&path, "community.example").is_err());
    assert!(
        common::host_storage::open_reconciled(
            &path,
            trust,
            settings.clone(),
            RealVerifier::default(),
            SigningKey::from_bytes(&[9; 32]),
            AdmissionKeyReconciliation {
                target: target(&signer),
                transitions: Vec::new()
            },
            || 1001
        )
        .is_err()
    );
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
}
