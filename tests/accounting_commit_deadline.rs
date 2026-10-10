//! Real proofs with an atomic host that blocks around its commit decision.
mod common;
use cblc::{
    Error,
    accounting::{AccountAcceptance, AccountRequest},
    accounting_ledger::{AccountLedger, AccountLedgerPolicy},
    storage::{AccountStorage, AtomicTransaction, CommitDeadline, Transaction},
};
use common::{
    Fixture,
    proofs::{self, RealVerifier},
};
use ed25519_dalek::SigningKey;
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    time::Duration,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum StopAt {
    StagedFrontier,
    Committed,
}
struct Pause {
    point: StopAt,
    entered: Sender<()>,
    resume: Receiver<()>,
}
impl Pause {
    fn wait(self) -> Result<(), Error> {
        self.entered.send(()).map_err(|_| Error::Storage)?;
        self.resume
            .recv_timeout(Duration::from_secs(180))
            .map_err(|_| Error::Storage)
    }
}
struct Host {
    store: cssr::MemoryStore,
    pauses: VecDeque<Pause>,
}
struct HostTransaction<'a> {
    inner: Box<dyn cssr::Transaction + 'a>,
    pauses: &'a mut VecDeque<Pause>,
}
impl HostTransaction<'_> {
    fn pause_at(&mut self, point: StopAt) -> Result<(), Error> {
        if let Some(pause) = self.pauses.pop_front_if(|pause| pause.point == point) {
            pause.wait()?;
        }
        Ok(())
    }
}
impl AccountStorage for Host {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        Ok(Transaction::new(Box::new(HostTransaction {
            inner: cssr::Storage::transaction(&mut self.store).map_err(|_| Error::Storage)?,
            pauses: &mut self.pauses,
        })))
    }
}
impl AtomicTransaction for HostTransaction<'_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.inner.get(key).map_err(|_| Error::Storage)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.inner.put(key, value).map_err(|_| Error::Storage)?;
        if key.first() == Some(&1) {
            self.pause_at(StopAt::StagedFrontier)?;
        }
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.inner.delete(key).map_err(|_| Error::Storage)
    }
    fn commit(self: Box<Self>) -> Result<(), Error> {
        self.inner.commit().map_err(|_| Error::Storage)
    }
    fn commit_before(self: Box<Self>, deadline: &CommitDeadline<'_>) -> Result<(), Error> {
        deadline.check()?;
        let Self { inner, pauses } = *self;
        inner.commit().map_err(|_| Error::Storage)?;
        if let Some(pause) = pauses.pop_front_if(|pause| pause.point == StopAt::Committed) {
            pause.wait()?;
        }
        Ok(())
    }
    fn rollback(self: Box<Self>) -> Result<(), Error> {
        self.inner.rollback().map_err(|_| Error::Storage)
    }
}
fn policy() -> AccountLedgerPolicy {
    AccountLedgerPolicy {
        account: proofs::record(0).statement.policy,
        max_authorization_seconds: 100,
        max_proof_bytes: 1024 * 1024,
        checkpoint_period_seconds: 1000,
    }
}
fn key(kind: u8, owner: &[u8; 32]) -> Vec<u8> {
    let mut result = vec![kind];
    result.extend_from_slice(&32_u64.to_be_bytes());
    result.extend_from_slice(owner);
    result
}
fn read(
    store: &mut cssr::MemoryStore,
    request: &AccountRequest,
) -> (Option<Vec<u8>>, Option<AccountAcceptance>) {
    let mut transaction = cssr::Storage::transaction(store).unwrap();
    let owner = &request.statement.owner;
    let frontier = transaction.get(&key(1, owner)).unwrap();
    let acceptance = transaction
        .get(&key(2, owner))
        .unwrap()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap());
    transaction.rollback().unwrap();
    (frontier, acceptance)
}
fn run(stops: &[(StopAt, u64)], expected_error: Error) {
    let point = stops.last().unwrap().0;
    let recovery_time = stops.iter().map(|(_, time)| *time).max().unwrap().max(110);
    let fixture = Fixture::new();
    let request = proofs::request(0, 10, &fixture);
    assert_eq!(request.expires_at, 180);
    let clock = Arc::new(AtomicU64::new(110));
    let store = cssr::MemoryStore::default();
    let mut observed = store.clone();
    let mut pauses = VecDeque::new();
    let mut controls = Vec::new();
    for &(point, delayed_time) in stops {
        let (entered, waiting) = mpsc::channel();
        let (resume, released) = mpsc::channel();
        pauses.push_back(Pause {
            point,
            entered,
            resume: released,
        });
        controls.push((waiting, resume, delayed_time));
    }
    let host = Host { store, pauses };
    let mut ledger = AccountLedger::with_store(
        host,
        fixture.trust.clone(),
        policy(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    ledger
        .admit_checkpoint(0, request.statement.enrollment_root)
        .unwrap();
    let original = read(&mut observed, &request);
    assert!(original.0.is_none() && original.1.is_none());
    let advanced = clock.clone();
    let controller = std::thread::spawn(move || {
        for (waiting, resume, delayed_time) in controls {
            waiting.recv_timeout(Duration::from_secs(180)).unwrap();
            advanced.store(delayed_time, Ordering::SeqCst);
            resume.send(()).unwrap();
        }
    });
    let apply = |ledger: &mut AccountLedger<RealVerifier>| {
        ledger.apply(
            &fixture.grant(7, &fixture.device),
            &fixture.authorize(7, &fixture.device),
            &request,
            || clock.load(Ordering::SeqCst),
        )
    };
    let result = apply(&mut ledger);
    controller.join().unwrap();
    assert_eq!(result, Err(expected_error));
    let after = read(&mut observed, &request);
    if point == StopAt::StagedFrontier {
        assert_eq!(
            after, original,
            "expired or rollback commit must discard staged frontier and acceptance"
        );
        // No expired operation was written: the original exact request can
        // still succeed during a valid window, with its real proof unchanged.
        clock.store(110, Ordering::SeqCst);
        let accepted = apply(&mut ledger).unwrap();
        assert_eq!(accepted.request_id, request.request_id);
        assert!(read(&mut observed, &request).0.is_some());
    } else {
        assert!(
            after.0.is_some(),
            "late acknowledgement does not undo a valid commit"
        );
        let committed = after.1.unwrap();
        assert_eq!(committed.accepted_at, 110);
        // Exact idempotent recovery returns the original historical response,
        // including after the operation window ended. It never writes twice.
        clock.store(recovery_time, Ordering::SeqCst);
        assert_eq!(apply(&mut ledger).unwrap(), committed);
        assert_eq!(read(&mut observed, &request).1.unwrap(), committed);
    }
}

#[test]
fn blocking_staged_put_cannot_commit_after_expiry_or_clock_rollback() {
    run(&[(StopAt::StagedFrontier, 180)], Error::Expired);
    run(&[(StopAt::StagedFrontier, 181)], Error::Expired);
    run(&[(StopAt::StagedFrontier, 109)], Error::ClockRollback);
}

#[test]
fn late_commit_return_refuses_fresh_authority_but_preserves_exact_recovery() {
    run(&[(StopAt::Committed, 180)], Error::Expired);
    run(&[(StopAt::Committed, 181)], Error::Expired);
    run(&[(StopAt::Committed, 109)], Error::ClockRollback);
}

#[test]
fn return_time_cannot_move_behind_a_later_valid_atomic_decision() {
    run(
        &[(StopAt::StagedFrontier, 150), (StopAt::Committed, 140)],
        Error::ClockRollback,
    );
}

#[test]
fn late_tuning_commit_requires_authenticated_reload_before_a_new_revision() {
    let fixture = Fixture::new();
    let clock = Arc::new(AtomicU64::new(110));
    let (entered, waiting) = mpsc::channel();
    let (resume, released) = mpsc::channel();
    let host = Host {
        store: cssr::MemoryStore::default(),
        pauses: VecDeque::from([Pause {
            point: StopAt::Committed,
            entered,
            resume: released,
        }]),
    };
    let mut ledger = AccountLedger::with_store(
        host,
        fixture.trust,
        policy(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    let initial = ledger.waiting_period().unwrap();
    assert_eq!(initial.revision, 0);
    assert_eq!(initial.seconds, 1000);
    let advanced = clock.clone();
    let controller = std::thread::spawn(move || {
        waiting.recv_timeout(Duration::from_secs(180)).unwrap();
        // The new 1500-second reservation horizon ends exactly at policy2000.
        advanced.store(500, Ordering::SeqCst);
        resume.send(()).unwrap();
    });
    let result = ledger.update_waiting_period(0, 1500, || clock.load(Ordering::SeqCst));
    controller.join().unwrap();
    assert_eq!(result, Err(Error::Expired));
    assert_eq!(ledger.waiting_period().unwrap(), initial);
    // A late response does not authorize a blind retry against the stale local
    // revision. The already committed change must first be read and validated.
    assert_eq!(
        ledger.update_waiting_period(0, 1000, || clock.load(Ordering::SeqCst)),
        Err(Error::PolicyMismatch)
    );
    let committed = ledger.reload_policy().unwrap();
    assert_eq!(committed.revision, 1);
    assert_eq!(committed.seconds, 1500);
    clock.store(501, Ordering::SeqCst);
    let next = ledger
        .update_waiting_period(1, 1000, || clock.load(Ordering::SeqCst))
        .unwrap();
    assert_eq!(next.revision, 2);
    assert_eq!(next.seconds, 1000);
    assert_eq!(ledger.reload_policy().unwrap(), next);
}
