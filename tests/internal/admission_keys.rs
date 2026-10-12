//! Real CSGN signatures and real RAM transactions; no proof verifier stands in.
use super::*;
use crate::storage::MemoryStore;

fn signer() -> csgn::Signer {
    csgn::Signer::new(
        "community-example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        1,
        2000,
    )
    .unwrap()
}
fn rotate(signer: &mut csgn::Signer, seed: u8, now: u64) -> Vec<u8> {
    let proof = signer
        .rotate_with_proof(csgn::SecretKey::from_seed(&mut [seed; 32]), now, 400)
        .unwrap();
    signer
        .acknowledge_transition(signer.ring_revision())
        .unwrap();
    proof
}
fn fixture() -> (Bootstrap, History, csgn::KeyRing) {
    let mut signer = signer();
    rotate(&mut signer, 2, 110);
    rotate(&mut signer, 3, 120);
    let bootstrap = Bootstrap {
        format: "cblc.admission-key-bootstrap.v1".into(),
        revision: signer.ring_revision(),
        policy_keys: signer.key_ring().to_cbor(),
    };
    let proof = rotate(&mut signer, 4, 130);
    let history = History {
        format: "cblc.admission-key-history.v1".into(),
        revision: signer.ring_revision(),
        transitions: vec![AcceptedTransition {
            revision: signer.ring_revision(),
            verified_at: 130,
            proof,
        }],
    };
    (bootstrap, history, signer.key_ring().clone())
}

#[test]
fn real_nonzero_bootstrap_and_unchanged_historical_proof_survive_reopen() {
    let (bootstrap, history, current) = fixture();
    assert_eq!(bootstrap.revision, 2);
    let previous = csgn::KeyRing::from_cbor(&bootstrap.policy_keys).unwrap();
    let mut store = MemoryStore::default();
    let mut tx = store.transaction().unwrap();
    tx.put(b"clock", &300u64).unwrap();
    let expected = AdmissionKeyState {
        revision: 2,
        policy_keys: previous.clone(),
    };
    assert_eq!(
        open(&mut tx, &previous, true, Some(&expected)).unwrap(),
        Some(expected)
    );
    tx.put(HISTORY, &history).unwrap();
    tx.commit().unwrap();
    let mut tx = store.transaction().unwrap();
    check_successor(&mut tx, &previous, &current).unwrap();
    let expected = AdmissionKeyState {
        revision: 3,
        policy_keys: current.clone(),
    };
    assert!(
        open(&mut tx, &current, false, Some(&expected))
            .unwrap()
            .is_some()
    );
    // Live adoption is now expired; only the exact durable earlier verification
    // can authenticate this historical successor, never grant live authority.
    assert!(csgn::verify_transition(&previous, &history.transitions[0].proof, 400).is_err());
    assert!(chain(&bootstrap, &history, 400).is_ok());
    let rollback = AdmissionKeyState {
        revision: 2,
        policy_keys: previous,
    };
    assert!(open(&mut tx, &current, false, Some(&rollback)).is_err());
    tx.rollback().unwrap();
}

#[test]
fn missing_metadata_never_initializes_an_existing_native_ledger() {
    let mut store = MemoryStore::default();
    let keys = signer().key_ring().clone();
    let expected = AdmissionKeyState {
        revision: 0,
        policy_keys: keys.clone(),
    };
    let mut tx = store.transaction().unwrap();
    tx.put(b"clock", &0u64).unwrap();
    assert!(matches!(
        open(&mut tx, &keys, false, Some(&expected)),
        Err(Error::UnsupportedCapability)
    ));
    assert!(tx.get::<Bootstrap>(BOOTSTRAP).unwrap().is_none());
    assert!(tx.get::<History>(HISTORY).unwrap().is_none());
    open(&mut tx, &keys, true, Some(&expected)).unwrap();
    tx.delete(HISTORY).unwrap();
    assert!(open(&mut tx, &keys, false, Some(&expected)).is_err());
    tx.rollback().unwrap();
}

#[test]
fn truncated_forked_tampered_retimed_or_unverified_history_refuses() {
    let (bootstrap, original, current) = fixture();
    for case in 0..8 {
        let mut history = original.clone();
        match case {
            0 => history.transitions.clear(),
            1 => history.revision -= 1,
            2 => history.transitions[0].revision += 1,
            3 => history.transitions[0].proof[0] ^= 1,
            4 => history.transitions[0].verified_at = 129,
            5 => history.transitions[0].verified_at = 400,
            6 => history.transitions[0].verified_at = 301,
            _ => history.transitions.push(history.transitions[0].clone()),
        }
        assert!(chain(&bootstrap, &history, 300).is_err());
    }
    let unrelated = csgn::Signer::new(
        "community-example",
        csgn::SecretKey::from_seed(&mut [9; 32]),
        1,
        2000,
    )
    .unwrap();
    let mut store = MemoryStore::default();
    let mut tx = store.transaction().unwrap();
    tx.put(b"clock", &300u64).unwrap();
    tx.put(BOOTSTRAP, &bootstrap).unwrap();
    tx.put(HISTORY, &original).unwrap();
    assert!(check_successor(&mut tx, unrelated.key_ring(), &current).is_err());
    assert!(check_successor(&mut tx, &current, unrelated.key_ring()).is_err());
    tx.rollback().unwrap();
}

#[test]
fn capacity_refuses_instead_of_dropping_any_original_transition() {
    let (bootstrap, mut history, _) = fixture();
    let original = history.transitions[0].clone();
    history.transitions = vec![original; MAX_TRANSITIONS + 1];
    assert_eq!(bounded(&history), Err(Error::Capacity));
    assert!(chain(&bootstrap, &history, 300).is_err());
    history.transitions.truncate(1);
    history.transitions[0].proof = vec![0; MAX_HISTORY_BYTES];
    assert_eq!(bounded(&history), Err(Error::Capacity));
}

#[test]
fn original_startup_probe_refuses_nonempty_missing_or_malformed_config() {
    let mut store = MemoryStore::default();
    assert_eq!(startup_clock_floor(&mut store).unwrap(), 0);
    let mut tx = store.transaction().unwrap();
    tx.put(b"orphaned-original-owner-row", &1u64).unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        startup_clock_floor(&mut store),
        Err(Error::Storage)
    ));
    let mut tx = store.transaction().unwrap();
    tx.put(b"config", &b"invalid config".to_vec()).unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        startup_clock_floor(&mut store),
        Err(Error::Storage)
    ));
    let mut tx = store.transaction().unwrap();
    assert_eq!(
        tx.get::<u64>(b"orphaned-original-owner-row").unwrap(),
        Some(1)
    );
    tx.rollback().unwrap();
}

#[test]
fn original_binary_owner_row_prevents_empty_store_clock_bootstrap() {
    let mut store = MemoryStore::default();
    let frontier_key = key(1, &[&[7; 32]]);
    let mut tx = store.transaction().unwrap();
    // An orphan in the original lowest binary owner namespace remains refusal,
    // even when the textual config and clock metadata are both missing.
    tx.put(&frontier_key, &1u64).unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        startup_clock_floor(&mut store),
        Err(Error::Storage)
    ));
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(&frontier_key).unwrap(), Some(1));
    assert!(tx.get::<Vec<u8>>(b"config").unwrap().is_none());
    assert!(tx.get::<u64>(b"clock").unwrap().is_none());
    tx.rollback().unwrap();
}

#[test]
fn reconciliation_transport_cannot_reorder_skip_duplicate_or_exceed_bounds() {
    let (bootstrap, history, current) = fixture();
    let proof = history.transitions[0].proof.clone();
    let target = AdmissionKeyState {
        revision: 3,
        policy_keys: current,
    };
    for transitions in [
        vec![(3, proof.clone()), (2, proof.clone())],
        vec![(1, proof.clone()), (3, proof.clone())],
        vec![(3, proof.clone()), (3, proof.clone())],
        vec![(4, proof.clone())],
        vec![(3, Vec::new())],
    ] {
        assert!(
            AdmissionKeyReconciliation {
                target: target.clone(),
                transitions
            }
            .check_shape()
            .is_err()
        );
    }
    assert_eq!(
        AdmissionKeyReconciliation {
            target: target.clone(),
            transitions: vec![(3, vec![0; MAX_HISTORY_BYTES])]
        }
        .check_shape(),
        Err(Error::Capacity)
    );
    assert_eq!(
        AdmissionKeyReconciliation {
            target,
            transitions: vec![(bootstrap.revision, proof); MAX_TRANSITIONS + 1]
        }
        .check_shape(),
        Err(Error::Capacity)
    );
}
