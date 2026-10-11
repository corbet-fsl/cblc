use super::*;

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
