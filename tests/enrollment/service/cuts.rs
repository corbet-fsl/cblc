use super::*;

fn write(path: &Path, community: &str, key: &[u8], value: Option<&serde_json::Value>) {
    let mut store = cssr::LibsqlStore::local(path, community).unwrap();
    let mut tx = cssr::Storage::transaction(&mut store).unwrap();
    if let Some(value) = value {
        tx.put(key, &serde_json::to_vec(value).unwrap()).unwrap();
    } else {
        tx.delete(key).unwrap();
    }
    tx.commit().unwrap();
}

#[test]
fn legacy_identical_current_root_gains_correspondence_but_orphan_receipt_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let limits = registry::config(&f);
    populate(&path, &f, &d, limits.clone());
    let now = Arc::new(AtomicU64::new(130));
    let owner = current(&f, &d);
    let mut source = producer(&path, &f, limits.clone(), now.clone());
    let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
    let root = pending.publication().root;
    // The original trusted local operation has no full-publication marker.
    let mut ledger = common::host_storage::open(
        &path,
        f.trust.clone(),
        policy(100),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    ledger.admit_checkpoint(1, root).unwrap();
    let mut ledger = AccountService::new(
        ledger,
        {
            let now = now.clone();
            move || now.load(Ordering::Acquire)
        },
        65536,
    )
    .unwrap();
    let installed = ledger
        .publish_pending_checkpoint(pending, owner.clone())
        .unwrap();
    source.acknowledge(installed).unwrap();
    assert_eq!(
        read(&path, &f.trust.community_id, &slot_key(1)),
        Some(serde_json::json!(root.to_vec()))
    );
    let mut marker = b"enrollment/installed/".to_vec();
    marker.extend_from_slice(&1_u64.to_be_bytes());
    assert!(read(&path, &f.trust.community_id, &marker).is_some());
    write(&path, &f.trust.community_id, &slot_key(1), None);
    let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
    assert!(matches!(
        ledger.publish_pending_checkpoint(pending, owner),
        Err(Error::Storage)
    ));
    assert!(read(&path, &f.trust.community_id, &slot_key(1)).is_none());
}

#[test]
fn configured_target_scope_digest_operator_and_period_are_independent_of_signed_object() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("source.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let limits = registry::config(&f);
    populate(&source_path, &f, &d, limits.clone());
    let now = Arc::new(AtomicU64::new(130));
    let owner = current(&f, &d);
    let mut source = producer(&source_path, &f, limits, now.clone());
    for changed in 0..4 {
        let mut selected = Fixture::new();
        let mut period = 100;
        let mut operator = 9;
        match changed {
            0 => selected.trust.community_id = "other".into(),
            1 => selected.trust.policy_digest = common::encoded(4),
            2 => operator = 8,
            _ => period = 101,
        }
        let path = dir.path().join(format!("target{changed}.db"));
        let mut ledger = target(&path, &selected, period, operator, now.clone());
        let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
        assert!(
            matches!(
                ledger.publish_pending_checkpoint(pending, owner.clone()),
                Err(Error::PolicyMismatch)
            ),
            "{changed}"
        );
        assert!(read(&path, &selected.trust.community_id, &slot_key(1)).is_none());
        assert_eq!(
            read(&path, &selected.trust.community_id, b"clock"),
            Some(serde_json::json!(0))
        );
    }
}

#[test]
fn original_exclusive_slot_end_refuses_old_object_and_clock_regression_never_renews_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let limits = registry::config(&f);
    populate(&path, &f, &d, limits.clone());
    let now = Arc::new(AtomicU64::new(130));
    let owner = current(&f, &d);
    let mut source = producer(&path, &f, limits, now.clone());
    let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
    let mut ledger = target(&path, &f, 100, 9, now.clone());
    now.store(200, Ordering::Release);
    assert!(matches!(
        ledger.publish_pending_checkpoint(pending, owner.clone()),
        Err(Error::Expired)
    ));
    assert!(read(&path, &f.trust.community_id, &slot_key(1)).is_none());
    now.store(129, Ordering::Release);
    assert!(matches!(
        prepare(&mut source, &f, 1, owner.clone()),
        Err(Error::ClockRollback)
    ));
    now.store(210, Ordering::Release);
    let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
    assert_eq!(pending.publication().slot, 2);
    assert_eq!(pending.publication().not_before, 200);
    assert_eq!(pending.publication().expires_at, 300);
    let installed = ledger.publish_pending_checkpoint(pending, owner).unwrap();
    source.acknowledge(installed).unwrap();
    assert!(source.checkpoint(1).unwrap().is_none());
    assert!(source.checkpoint(2).unwrap().is_some());
}

#[test]
fn changed_original_cut_or_config_cannot_rebind_an_already_installed_full_object() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let d = delegation(&f);
    for config_change in [false, true] {
        let path = dir.path().join(format!("common{config_change}.db"));
        let limits = registry::config(&f);
        populate(&path, &f, &d, limits.clone());
        let now = Arc::new(AtomicU64::new(130));
        let owner = current(&f, &d);
        let mut source = producer(&path, &f, limits.clone(), now.clone());
        let mut ledger = target(&path, &f, 100, 9, now.clone());
        let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
        let root = pending.publication().root;
        let installed = ledger
            .publish_pending_checkpoint(pending, owner.clone())
            .unwrap();
        drop(installed);
        drop(source);
        let mut selected = limits;
        if config_change {
            selected.max_retained_slots += 1;
            write(
                &path,
                &f.trust.community_id,
                b"enrollment/config",
                Some(&serde_json::to_value(&selected).unwrap()),
            );
        } else {
            let mut frozen = read(&path, &f.trust.community_id, &pending_key(1)).unwrap();
            frozen["checked_at"] = serde_json::json!(131);
            write(&path, &f.trust.community_id, &pending_key(1), Some(&frozen));
        }
        now.store(132, Ordering::Release);
        let mut source = producer(&path, &f, selected, now.clone());
        let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
        assert!(matches!(
            ledger.publish_pending_checkpoint(pending, owner),
            Err(Error::PolicyMismatch)
        ));
        assert_eq!(
            read(&path, &f.trust.community_id, &slot_key(1)),
            Some(serde_json::json!(root.to_vec()))
        );
    }
}

#[test]
fn corrupt_frozen_root_or_old_object_relabelled_as_new_slot_cannot_create_pending_capability() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let d = delegation(&f);
    for relabel in [false, true] {
        let path = dir.path().join(format!("common{relabel}.db"));
        let limits = registry::config(&f);
        populate(&path, &f, &d, limits.clone());
        let now = Arc::new(AtomicU64::new(130));
        let owner = current(&f, &d);
        let mut source = producer(&path, &f, limits, now.clone());
        drop(prepare(&mut source, &f, 1, owner.clone()).unwrap());
        let mut stored = read(&path, &f.trust.community_id, &pending_key(1)).unwrap();
        let mut publication: EnrollmentPublication =
            serde_json::from_value(stored["publication"].clone()).unwrap();
        if relabel {
            publication.slot = 2;
            publication.not_before = 200;
            publication.expires_at = 300;
            now.store(210, Ordering::Release);
        } else {
            publication.root = czkp::poseidon::integer(7);
        }
        // Even a genuine configured operator signature does not replace the
        // retained original cut and the complete rebuilt native tree relation.
        publication.signature = B64.encode(
            &SigningKey::from_bytes(&[9; 32])
                .sign(&publication.signing_bytes().unwrap())
                .to_bytes(),
        );
        stored["publication"] = serde_json::to_value(publication).unwrap();
        write(
            &path,
            &f.trust.community_id,
            &pending_key(if relabel { 2 } else { 1 }),
            Some(&stored),
        );
        assert!(matches!(
            prepare(&mut source, &f, 1, owner),
            Err(Error::Admission)
        ));
        assert!(
            read(
                &path,
                &f.trust.community_id,
                &slot_key(if relabel { 2 } else { 1 })
            )
            .is_none()
        );
    }
}

#[test]
fn retention_bound_is_explicit_and_never_rebuilds_pruned_installed_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let mut limits = registry::config(&f);
    limits.max_retained_slots = 1;
    populate(&path, &f, &d, limits.clone());
    let now = Arc::new(AtomicU64::new(130));
    let owner = current(&f, &d);
    let mut source = producer(&path, &f, limits, now.clone());
    let mut ledger = target(&path, &f, 100, 9, now.clone());
    for time in [130, 210] {
        now.store(time, Ordering::Release);
        let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
        let installed = ledger
            .publish_pending_checkpoint(pending, owner.clone())
            .unwrap();
        source.acknowledge(installed).unwrap();
    }
    assert!(source.checkpoint(1).unwrap().is_none());
    assert!(source.checkpoint(2).unwrap().is_some());
    assert!(read(&path, &f.trust.community_id, &pending_key(1)).is_none());
}

#[test]
fn exclusive_expiry_at_actual_ledger_commit_discards_root_marker_and_clock_together() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let limits = registry::config(&f);
    populate(&path, &f, &d, limits.clone());
    let now = Arc::new(AtomicU64::new(130));
    let owner = current(&f, &d);
    let mut source = producer(&path, &f, limits, now);
    let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
    let ledger = common::host_storage::open(
        &path,
        f.trust.clone(),
        policy(100),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    let calls = std::cell::Cell::new(0);
    let mut ledger = AccountService::new(
        ledger,
        || {
            let n = calls.get();
            calls.set(n + 1);
            if n == 0 { 130 } else { 200 }
        },
        65536,
    )
    .unwrap();
    assert!(matches!(
        ledger.publish_pending_checkpoint(pending, owner),
        Err(Error::Expired)
    ));
    assert_eq!(calls.get(), 2);
    assert!(read(&path, &f.trust.community_id, &slot_key(1)).is_none());
    let mut marker = b"enrollment/installed/".to_vec();
    marker.extend_from_slice(&1_u64.to_be_bytes());
    assert!(read(&path, &f.trust.community_id, &marker).is_none());
    assert_eq!(
        read(&path, &f.trust.community_id, b"clock"),
        Some(serde_json::json!(130))
    );
}

#[test]
fn explicit_publication_byte_budget_refuses_before_persisting_any_pending_object() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let mut limits = registry::config(&f);
    limits.max_publication_bytes = 1;
    populate(&path, &f, &d, limits.clone());
    let mut source = producer(&path, &f, limits, Arc::new(AtomicU64::new(130)));
    assert!(matches!(
        prepare(&mut source, &f, 1, current(&f, &d)),
        Err(Error::Capacity)
    ));
    assert!(read(&path, &f.trust.community_id, &pending_key(1)).is_none());
    assert_eq!(
        read(&path, &f.trust.community_id, b"clock"),
        Some(serde_json::json!(130))
    );
}
