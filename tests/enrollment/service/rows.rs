use super::*;

#[test]
fn fresh_history_is_absent_only_for_the_actual_empty_namespace_without_any_write() {
    use cblc::storage::{AccountStorage, MemoryStore};
    let f = Fixture::new();
    let mut shared = MemoryStore::default();
    let mut publisher = EnrollmentService::new(
        EnrollmentStore::new(shared.clone(), registry::config(&f)).unwrap(),
        SigningKey::from_bytes(&[9; 32]),
        || 150,
    )
    .unwrap();
    assert!(publisher.checkpoint(1).unwrap().is_none());
    assert!(matches!(publisher.checkpoint(2), Err(Error::InvalidInput)));
    let mut tx = AccountStorage::transaction(&mut shared).unwrap();
    assert!(
        tx.get::<serde_json::Value>(b"enrollment/config")
            .unwrap()
            .is_none()
    );
    assert!(tx.get::<u64>(b"clock").unwrap().is_none());
    assert!(
        tx.current_range::<serde_json::Value>(b"enrollment/", b"enrollment0", 1)
            .unwrap()
            .is_empty()
    );
    tx.rollback().unwrap();

    // A retained non-member key also makes missing configuration corruption.
    let mut tx = AccountStorage::transaction(&mut shared).unwrap();
    tx.put(
        b"enrollment/pending/orphan",
        &serde_json::json!({"orphan":true}),
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(matches!(publisher.checkpoint(1), Err(Error::Storage)));
    let mut tx = AccountStorage::transaction(&mut shared).unwrap();
    assert_eq!(
        tx.get::<serde_json::Value>(b"enrollment/pending/orphan")
            .unwrap(),
        Some(serde_json::json!({"orphan":true}))
    );
    assert!(tx.get::<u64>(b"clock").unwrap().is_none());
    tx.rollback().unwrap();
}

#[test]
fn missing_config_real_signed_member_malformed_row_and_clock_rollback_never_mean_absence() {
    use cblc::storage::{AccountStorage, MemoryStore};
    let f = Fixture::new();
    let d = delegation(&f);
    let limits = registry::config(&f);
    let mut shared = MemoryStore::default();
    let mut store = EnrollmentStore::new(shared.clone(), limits.clone()).unwrap();
    let actual = registry::enroll(&mut store, &f, &d, 150).unwrap();
    let mut tx = AccountStorage::transaction(&mut shared).unwrap();
    tx.delete(b"enrollment/config").unwrap();
    tx.commit().unwrap();
    let mut publisher =
        EnrollmentService::new(store, SigningKey::from_bytes(&[9; 32]), || 150).unwrap();
    assert!(matches!(publisher.checkpoint(1), Err(Error::Storage)));
    let mut key = b"enrollment/member/".to_vec();
    key.extend_from_slice(actual.member_id.as_bytes());
    let mut tx = AccountStorage::transaction(&mut shared).unwrap();
    let retained: StoredEnrollment = tx.get(&key).unwrap().unwrap();
    assert_eq!(retained.entry(), &actual);
    assert!(
        tx.get::<EnrollmentConfig>(b"enrollment/config")
            .unwrap()
            .is_none()
    );
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), Some(150));
    tx.rollback().unwrap();

    let mut malformed = MemoryStore::default();
    let mut tx = cssr::Storage::transaction(&mut malformed).unwrap();
    tx.put(b"enrollment/pending/malformed", b"not-json")
        .unwrap();
    tx.commit().unwrap();
    let mut publisher = EnrollmentService::new(
        EnrollmentStore::new(malformed, limits.clone()).unwrap(),
        SigningKey::from_bytes(&[9; 32]),
        || 150,
    )
    .unwrap();
    assert!(matches!(publisher.checkpoint(1), Err(Error::Storage)));

    let mut rollback = MemoryStore::default();
    let mut tx = AccountStorage::transaction(&mut rollback).unwrap();
    tx.put(b"clock", &151_u64).unwrap();
    tx.commit().unwrap();
    let mut publisher = EnrollmentService::new(
        EnrollmentStore::new(rollback.clone(), limits).unwrap(),
        SigningKey::from_bytes(&[9; 32]),
        || 150,
    )
    .unwrap();
    assert!(matches!(publisher.checkpoint(1), Err(Error::ClockRollback)));
    let mut tx = AccountStorage::transaction(&mut rollback).unwrap();
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), Some(151));
    tx.rollback().unwrap();
}

#[test]
fn malformed_expired_native_leaf_is_not_omitted_while_another_member_is_eligible() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let limits = registry::config(&f);
    populate(&path, &f, &d, limits.clone());
    let mut old = d.clone();
    old.admission = f.grant(8, &f.device);
    old.authorization = f.authorize(8, &f.device);
    old.expires_at = 599;
    resign(&mut old, &f.device);
    populate(&path, &f, &old, limits.clone());
    let mut live = d;
    live.issued_at = 601;
    live.expires_at = 800;
    resign(&mut live, &f.device);
    let mut store = common::host_storage::open_enrollment(&path, limits.clone()).unwrap();
    registry::enroll(&mut store, &f, &live, 602).unwrap();
    drop(store);
    // Deliberate genuine storage corruption of an otherwise expired row. The
    // new intake already refuses such a field; it cannot be used as cleanup.
    let mut key = b"enrollment/member/".to_vec();
    key.extend_from_slice(old.admission.member_id.as_bytes());
    let mut record = read(&path, &f.trust.community_id, &key).unwrap();
    old.state_secret_commitment = HEX.encode(&[255; 32]);
    resign(&mut old, &f.device);
    record["record"]["delegation"] = serde_json::to_value(&old).unwrap();
    record["record"]["entry"]["secretHash"] = serde_json::json!(old.state_secret_commitment);
    record["record"]["entry"]["delegationDigest"] =
        serde_json::json!(HEX.encode(&old.digest().unwrap()));
    let mut sql = cssr::LibsqlStore::local(&path, &f.trust.community_id).unwrap();
    let mut tx = cssr::Storage::transaction(&mut sql).unwrap();
    tx.put(&key, &serde_json::to_vec(&record).unwrap()).unwrap();
    tx.commit().unwrap();
    let mut source = producer(&path, &f, limits, Arc::new(AtomicU64::new(610)));
    assert!(matches!(
        prepare(&mut source, &f, 1, current(&f, &live)),
        Err(Error::InvalidInput)
    ));
    assert!(read(&path, &f.trust.community_id, &pending_key(6)).is_none());
    assert_eq!(
        read(&path, &f.trust.community_id, b"clock"),
        Some(serde_json::json!(602))
    );
}

#[test]
fn total_retained_publication_bytes_prune_even_when_slot_count_would_allow_both() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let d = delegation(&f);
    let now = Arc::new(AtomicU64::new(130));
    let owner = current(&f, &d);
    // Measure the ACTUAL signed owner output, then configure that explicit
    // deployment budget on a fresh store. No proof/material is fabricated.
    let measure = dir.path().join("measure.db");
    let limits = registry::config(&f);
    populate(&measure, &f, &d, limits.clone());
    let mut measured = producer(&measure, &f, limits.clone(), now.clone());
    let pending = prepare(&mut measured, &f, 1, owner.clone()).unwrap();
    let budget = serde_json::to_vec(pending.publication()).unwrap().len() as u64;
    drop(pending);
    drop(measured);
    let path = dir.path().join("common.db");
    let mut limits = limits;
    limits.max_publication_bytes = budget;
    limits.max_retained_slots = 2;
    populate(&path, &f, &d, limits.clone());
    let mut source = producer(&path, &f, limits, now.clone());
    let mut ledger = target(&path, &f, 100, 9, now.clone());
    for time in [130, 210] {
        now.store(time, Ordering::Release);
        let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
        assert_eq!(
            serde_json::to_vec(pending.publication()).unwrap().len() as u64,
            budget
        );
        let installed = ledger
            .publish_pending_checkpoint(pending, owner.clone())
            .unwrap();
        source.acknowledge(installed).unwrap();
    }
    assert!(source.checkpoint(1).unwrap().is_none());
    assert!(source.checkpoint(2).unwrap().is_some());
    assert!(read(&path, &f.trust.community_id, &pending_key(1)).is_none());
}
