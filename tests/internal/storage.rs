use super::*;
#[test]
fn memory_transactions_commit_rollback_drop_and_delete_atomically() {
    let mut store = MemoryStore::default();
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), None);
    tx.put(b"state", &7u64).unwrap();
    tx.commit().unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(b"state", &9u64).unwrap();
    tx.rollback().unwrap();
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), Some(7));
    tx.delete(b"state").unwrap();
    drop(tx);
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), Some(7));
    tx.delete(b"state").unwrap();
    tx.commit().unwrap();
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), None);
    // Serialization errors are sanitized and do not commit partial metadata.
    let invalid = std::collections::BTreeMap::from([(vec![1u8], 1)]);
    assert!(matches!(tx.put(b"bad", &invalid), Err(Error::Storage)));
    tx.put(b"state", &"wrong type").unwrap();
    assert!(matches!(tx.get::<u64>(b"state"), Err(Error::Storage)));
}
#[test]
fn poisoned_upstream_memory_is_refused() {
    let store = MemoryStore::default();
    let mut other = store.clone();
    let _ = std::thread::spawn(move || {
        let _tx = other.transaction().unwrap();
        panic!("test poison");
    })
    .join();
    let mut store = store;
    assert!(matches!(store.transaction(), Err(Error::Storage)));
}
// Upstream transaction errors are an integration boundary, not own logic.
struct Unavailable;
impl cssr::Transaction for Unavailable {
    fn get(&mut self, _: &[u8]) -> cssr::Result<Option<Vec<u8>>> {
        Err(cssr::Error)
    }
    fn put(&mut self, _: &[u8], _: &[u8]) -> cssr::Result<()> {
        Err(cssr::Error)
    }
    fn delete(&mut self, _: &[u8]) -> cssr::Result<()> {
        Err(cssr::Error)
    }
    fn commit(self: Box<Self>) -> cssr::Result<()> {
        Err(cssr::Error)
    }
    fn rollback(self: Box<Self>) -> cssr::Result<()> {
        Err(cssr::Error)
    }
}
#[test]
fn upstream_failures_cannot_become_success_or_expose_details() {
    let mut tx = Transaction::new(Box::new(MemoryTransaction(Box::new(Unavailable))));
    assert!(matches!(tx.get::<u64>(b"key"), Err(Error::Storage)));
    assert!(matches!(
        tx.current_range::<u64>(b"a", b"b", 2),
        Err(Error::Storage)
    ));
    assert!(matches!(tx.put(b"key", &1), Err(Error::Storage)));
    assert!(matches!(tx.delete(b"key"), Err(Error::Storage)));
    assert!(matches!(tx.commit(), Err(Error::Storage)));
    let tx = Transaction::new(Box::new(MemoryTransaction(Box::new(Unavailable))));
    assert!(matches!(tx.rollback(), Err(Error::Storage)));
    let tx = Transaction::new(Box::new(MemoryTransaction(Box::new(Unavailable))));
    assert!(matches!(
        tx.commit_before(&CommitDeadline::new(&|| 10, 10, 20)),
        Err(Error::Storage)
    ));
}

#[test]
fn current_snapshots_share_staged_memory_and_live_commit_deadline() {
    let mut store = MemoryStore::default();
    let mut tx = store.transaction().unwrap();
    tx.put(b"aa", &1_u64).unwrap();
    tx.put(b"ab", &2_u64).unwrap();
    tx.put(b"ba", &3_u64).unwrap();
    assert_eq!(
        tx.current_range::<u64>(b"a", b"b", 1).unwrap(),
        vec![(b"aa".to_vec(), 1)]
    );
    assert_eq!(
        tx.current_range::<u64>(b"a", b"b", (1 << 20) + 1).unwrap(),
        vec![(b"aa".to_vec(), 1), (b"ab".to_vec(), 2)]
    );
    tx.delete(b"aa").unwrap();
    tx.put(b"ab", &4_u64).unwrap();
    assert_eq!(
        tx.current_range::<u64>(b"a", b"b", 3).unwrap(),
        vec![(b"ab".to_vec(), 4)]
    );
    // The snapshot does not bypass the original live commit decision.
    assert_eq!(
        tx.commit_before(&CommitDeadline::new(&|| 20, 10, 20)),
        Err(Error::Expired)
    );
    let mut tx = store.transaction().unwrap();
    assert!(tx.current_range::<u64>(b"a", b"c", 3).unwrap().is_empty());
    tx.put(b"ab", &5_u64).unwrap();
    tx.commit_before(&CommitDeadline::new(&|| 19, 10, 20))
        .unwrap();
    let mut tx = store.transaction().unwrap();
    assert_eq!(
        tx.current_range::<u64>(b"a", b"b", 3).unwrap(),
        vec![(b"ab".to_vec(), 5)]
    );
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), Some(19));
    tx.put(b"aa", &"wrong type").unwrap();
    assert!(matches!(
        tx.current_range::<u64>(b"a", b"b", 3),
        Err(Error::Storage)
    ));
    tx.rollback().unwrap();
}

// A caller-owned adapter can retain its exact-key operations without silently
// claiming to support a complete current snapshot.
struct ExactOnly<'a>(Transaction<'a>);
impl AtomicTransaction for ExactOnly<'_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.0.0.get(key)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.0.0.put(key, value)
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.0.0.delete(key)
    }
    fn commit(self: Box<Self>) -> Result<(), Error> {
        self.0.commit()
    }
    fn commit_before(self: Box<Self>, deadline: &CommitDeadline<'_>) -> Result<(), Error> {
        self.0.commit_before(deadline)
    }
    fn rollback(self: Box<Self>) -> Result<(), Error> {
        self.0.rollback()
    }
}

#[test]
fn unsupported_host_snapshot_is_not_an_empty_community() {
    let mut store = MemoryStore::default();
    let mut tx = Transaction::new(Box::new(ExactOnly(store.transaction().unwrap())));
    tx.put(b"aa", &9_u64).unwrap();
    assert_eq!(tx.get::<u64>(b"aa").unwrap(), Some(9));
    assert!(matches!(
        tx.current_range::<u64>(b"a", b"b", 3),
        Err(Error::UnsupportedCapability)
    ));
    tx.rollback().unwrap();
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"aa").unwrap(), None);
}

// Preserve the real staged RAM writes but refuse at the upstream commit edge.
struct CommitFailure<'a>(Box<dyn cssr::Transaction + 'a>);
impl cssr::Transaction for CommitFailure<'_> {
    fn get(&mut self, key: &[u8]) -> cssr::Result<Option<Vec<u8>>> {
        self.0.get(key)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> cssr::Result<()> {
        self.0.put(key, value)
    }
    fn delete(&mut self, key: &[u8]) -> cssr::Result<()> {
        self.0.delete(key)
    }
    fn commit(self: Box<Self>) -> cssr::Result<()> {
        Err(cssr::Error)
    }
    fn rollback(self: Box<Self>) -> cssr::Result<()> {
        self.0.rollback()
    }
}

#[test]
fn failed_upstream_commit_discards_its_staged_clock_record_and_state() {
    let mut store = MemoryStore::default();
    let inner = cssr::Storage::transaction(&mut store).unwrap();
    let mut tx = Transaction::new(Box::new(MemoryTransaction(Box::new(CommitFailure(inner)))));
    tx.put(b"state", &1u64).unwrap();
    assert_eq!(
        tx.commit_before(&CommitDeadline::new(&|| 19, 10, 20)),
        Err(Error::Storage)
    );
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), None);
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), None);
}

#[test]
fn live_commit_deadline_refuses_expiry_and_clock_rollback_before_memory_swap() {
    let mut store = MemoryStore::default();
    for now in [0, 9, czkp::MAX_INTEGER + 1, 20] {
        let mut tx = store.transaction().unwrap();
        tx.put(b"state", &1u64).unwrap();
        let result = tx.commit_before(&CommitDeadline::new(&|| now, 10, 20));
        assert_eq!(
            result,
            Err(if now == 20 {
                Error::Expired
            } else {
                Error::ClockRollback
            })
        );
        let mut tx = store.transaction().unwrap();
        assert_eq!(tx.get::<u64>(b"state").unwrap(), None);
    }
    let mut tx = store.transaction().unwrap();
    tx.put(b"state", &2u64).unwrap();
    tx.commit_before(&CommitDeadline::new(&|| 19, 10, 20))
        .unwrap();
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), Some(2));
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), Some(19));
}

#[test]
fn late_successful_commit_is_expired_fresh_authority_and_keeps_committed_state() {
    let mut store = MemoryStore::default();
    let calls = std::cell::Cell::new(0);
    let clock = || {
        let n = calls.get();
        calls.set(n + 1);
        if n == 0 { 19 } else { 20 }
    };
    let mut tx = store.transaction().unwrap();
    tx.put(b"request", &7u64).unwrap();
    assert_eq!(
        tx.commit_before(&CommitDeadline::new(&clock, 10, 20)),
        Err(Error::Expired)
    );
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"request").unwrap(), Some(7));
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), Some(19));
}

#[test]
fn return_clock_cannot_move_behind_the_atomic_decision_observation() {
    let mut store = MemoryStore::default();
    let calls = std::cell::Cell::new(0);
    let clock = || {
        let n = calls.get();
        calls.set(n + 1);
        if n == 0 { 19 } else { 18 }
    };
    let mut tx = store.transaction().unwrap();
    tx.put(b"request", &8u64).unwrap();
    assert_eq!(
        tx.commit_before(&CommitDeadline::new(&clock, 10, 20)),
        Err(Error::ClockRollback)
    );
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"request").unwrap(), Some(8));
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), Some(19));
}
