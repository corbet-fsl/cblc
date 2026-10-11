use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct Current {
    allowed: AtomicBool,
    checked: AtomicU64,
    clock: Arc<AtomicU64>,
    advance: bool,
}
impl CommitAuthority for Current {
    fn check(&self, observed: u64) -> Result<(), Error> {
        self.checked.store(observed, Ordering::Release);
        if !self.allowed.load(Ordering::Acquire) {
            return Err(Error::Admission);
        }
        if self.advance {
            self.clock.fetch_add(1, Ordering::AcqRel);
        }
        Ok(())
    }
}
fn current(allowed: bool, advance: bool) -> Arc<Current> {
    Arc::new(Current {
        allowed: AtomicBool::new(allowed),
        checked: AtomicU64::new(0),
        clock: Arc::new(AtomicU64::new(10)),
        advance,
    })
}

#[test]
fn revocation_after_staging_discards_state_and_clock_together() {
    let mut durable = MemoryStore::default();
    let (mut store, scope) = AuthorityScope::wrap(durable.clone());
    let authority = current(true, false);
    let _guard = scope.enter(authority.clone()).unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(b"state", &7_u64).unwrap();
    authority.allowed.store(false, Ordering::Release);
    let clock = || authority.clock.load(Ordering::Acquire);
    assert_eq!(
        tx.commit_before(&CommitDeadline::new(&clock, 10, 20)),
        Err(Error::Admission)
    );
    assert_eq!(authority.checked.load(Ordering::Acquire), 10);
    let mut tx = durable.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), None);
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), None);
}

#[test]
fn authorized_state_and_actual_decision_clock_commit_together() {
    let mut durable = MemoryStore::default();
    let (mut store, scope) = AuthorityScope::wrap(durable.clone());
    let authority = current(true, false);
    let _guard = scope.enter(authority.clone()).unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(b"state", &7_u64).unwrap();
    authority.clock.store(12, Ordering::Release);
    let clock = || authority.clock.load(Ordering::Acquire);
    tx.commit_before(&CommitDeadline::new(&clock, 10, 20))
        .unwrap();
    assert_eq!(authority.checked.load(Ordering::Acquire), 12);
    let mut tx = durable.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), Some(7));
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), Some(12));
}

#[test]
fn scheduled_boundary_crossed_inside_owner_reads_refuses_commit() {
    let mut durable = MemoryStore::default();
    let (mut store, scope) = AuthorityScope::wrap(durable.clone());
    let authority = current(true, true);
    let _guard = scope.enter(authority.clone()).unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(b"state", &7_u64).unwrap();
    let clock = || authority.clock.load(Ordering::Acquire);
    assert_eq!(
        tx.commit_before(&CommitDeadline::new(&clock, 10, 20)),
        Err(Error::Expired)
    );
    assert_eq!(
        durable.transaction().unwrap().get::<u64>(b"state").unwrap(),
        None
    );
}

#[test]
fn transactions_retain_their_exact_owner_after_scope_drop_and_replacement() {
    let (mut store, scope) = AuthorityScope::wrap(MemoryStore::default());
    let original = current(false, false);
    let guard = scope.enter(original.clone()).unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(b"state", &7_u64).unwrap();
    drop(guard);
    let replacement = current(true, false);
    let _replacement = scope.enter(replacement.clone()).unwrap();
    assert_eq!(
        tx.commit_before(&CommitDeadline::new(&|| 10, 10, 20)),
        Err(Error::Admission)
    );
    assert_eq!(original.checked.load(Ordering::Acquire), 10);
    assert_eq!(replacement.checked.load(Ordering::Acquire), 0);
}

#[test]
fn member_scope_refuses_bare_commit_and_nested_scope_but_host_can_commit() {
    let (mut store, scope) = AuthorityScope::wrap(MemoryStore::default());
    let guard = scope.enter(current(true, false)).unwrap();
    assert!(matches!(
        scope.enter(current(true, false)),
        Err(Error::Storage)
    ));
    let mut tx = store.transaction().unwrap();
    tx.put(b"state", &7_u64).unwrap();
    assert_eq!(tx.commit(), Err(Error::Admission));
    drop(guard);
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), None);
    tx.put(b"host", &1_u64).unwrap();
    tx.commit().unwrap();
}

#[test]
fn authenticated_read_requires_current_owner_without_persisting_clock() {
    let mut durable = MemoryStore::default();
    let (mut store, scope) = AuthorityScope::wrap(durable.clone());
    let authority = current(false, false);
    let _guard = scope.enter(authority.clone()).unwrap();
    assert_eq!(
        store
            .transaction()
            .unwrap()
            .rollback_before(&CommitDeadline::new(&|| 10, 10, 20)),
        Err(Error::Admission)
    );
    authority.allowed.store(true, Ordering::Release);
    store
        .transaction()
        .unwrap()
        .rollback_before(&CommitDeadline::new(&|| 10, 10, 20))
        .unwrap();
    assert_eq!(
        durable.transaction().unwrap().get::<u64>(b"clock").unwrap(),
        None
    );
}

#[test]
fn panic_poisons_service_scope_instead_of_resetting_authority() {
    let (mut store, scope) = AuthorityScope::wrap(MemoryStore::default());
    let worker = scope.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = worker.enter(current(true, false)).unwrap();
            panic!("cancelled owner callback");
        })
        .join()
        .is_err()
    );
    assert!(matches!(
        scope.enter(current(true, false)),
        Err(Error::Storage)
    ));
    assert!(matches!(store.transaction(), Err(Error::Storage)));
}

// A host that violates the mandatory callback contract cannot report success.
// Its already persisted state is uncertain, never represented as a rollback.
struct MissingDecision(MemoryStore);
impl AccountStorage for MissingDecision {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        Ok(Transaction::new(Box::new(MissingDecisionTransaction(
            self.0.transaction()?.0,
        ))))
    }
}
struct MissingDecisionTransaction<'a>(Box<dyn AtomicTransaction + 'a>);
impl AtomicTransaction for MissingDecisionTransaction<'_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.0.get(key)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.0.put(key, value)
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.0.delete(key)
    }
    fn commit(self: Box<Self>) -> Result<(), Error> {
        self.0.commit()
    }
    fn commit_before(self: Box<Self>, _: &CommitDeadline<'_>) -> Result<(), Error> {
        self.0.commit()
    }
    fn rollback(self: Box<Self>) -> Result<(), Error> {
        self.0.rollback()
    }
    fn rollback_before(self: Box<Self>, _: &CommitDeadline<'_>) -> Result<(), Error> {
        self.0.rollback()
    }
}

#[test]
fn missing_host_decision_reports_uncertain_commit_and_withholds_read() {
    let mut durable = MemoryStore::default();
    let (mut store, scope) = AuthorityScope::wrap(MissingDecision(durable.clone()));
    let authority = current(false, false);
    let _guard = scope.enter(authority.clone()).unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(b"state", &7_u64).unwrap();
    assert_eq!(
        tx.commit_before(&CommitDeadline::new(&|| 10, 10, 20)),
        Err(Error::Storage)
    );
    assert_eq!(authority.checked.load(Ordering::Acquire), 0);
    assert_eq!(
        durable.transaction().unwrap().get::<u64>(b"state").unwrap(),
        Some(7)
    );
    assert_eq!(
        store
            .transaction()
            .unwrap()
            .rollback_before(&CommitDeadline::new(&|| 10, 10, 20)),
        Err(Error::Storage)
    );
}
