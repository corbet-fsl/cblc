//! Actual signed owners, caller SQL, and the original common slot CAS.
use super::*;
use cblc::{
    accounting::AccountPolicy, accounting_ledger::AccountLedgerPolicy,
    accounting_service::AccountService, storage::CommitAuthority,
};
use common::proofs::RealVerifier;
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

#[path = "service/cuts.rs"]
mod cuts;
#[path = "service/rows.rs"]
mod rows;

// Independent current expectation plus real Policy/root/device signatures.
// This is a storage-owner fixture, not an accepting proof or role verifier.
struct Current {
    delegation: Mutex<AccountingDelegation>,
    trust: cblc::admission::AdmissionTrust,
    epoch: AtomicU64,
}
impl CommitAuthority for Current {
    fn check(&self, now: u64) -> Result<(), Error> {
        let delegation = self.delegation.lock().map_err(|_| Error::Storage)?;
        verify_delegation(
            &delegation,
            ExpectedAdmission {
                trust: &self.trust,
                policy_epoch: self.epoch.load(Ordering::Acquire),
                passport_policy_digest: &common::encoded(10),
            },
            now,
        )
        .map(|_| ())
    }
}
fn current(f: &Fixture, d: &AccountingDelegation) -> Arc<Current> {
    Arc::new(Current {
        delegation: Mutex::new(d.clone()),
        trust: f.trust.clone(),
        epoch: AtomicU64::new(1),
    })
}
fn policy(period: u64) -> AccountLedgerPolicy {
    // Original existing host fixture policy, with explicit checkpoint cadence.
    AccountLedgerPolicy {
        account: AccountPolicy {
            initial_credit: 3,
            maximum_available: 4,
            outgoing_reservation: 1,
            incoming_reservation: 1,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 2000,
            newcomer_period: 100,
            rate_window: 1000,
            newcomer_admissions: 2,
            maximum_admissions: 4,
            refill_period: 100,
            refill_units: 1,
            abandon_after: 1000,
        },
        max_authorization_seconds: 100,
        max_proof_bytes: 1024 * 1024,
        checkpoint_period_seconds: period,
    }
}
fn producer(
    path: &Path,
    f: &Fixture,
    limits: EnrollmentConfig,
    now: Arc<AtomicU64>,
) -> EnrollmentService<impl Fn() -> u64> {
    assert_eq!(limits.community_id, f.trust.community_id);
    assert_eq!(limits.policy_digest, f.trust.policy_digest);
    EnrollmentService::new(
        common::host_storage::open_enrollment(path, limits).unwrap(),
        SigningKey::from_bytes(&[9; 32]),
        move || now.load(Ordering::Acquire),
    )
    .unwrap()
}
fn target(
    path: &Path,
    f: &Fixture,
    period: u64,
    operator: u8,
    now: Arc<AtomicU64>,
) -> AccountService<RealVerifier, impl Fn() -> u64> {
    let ledger = common::host_storage::open(
        path,
        f.trust.clone(),
        policy(period),
        RealVerifier::default(),
        SigningKey::from_bytes(&[operator; 32]),
    )
    .unwrap();
    AccountService::new(ledger, move || now.load(Ordering::Acquire), 65536).unwrap()
}
fn populate(path: &Path, f: &Fixture, d: &AccountingDelegation, limits: EnrollmentConfig) {
    // Initialize the ACTUAL accounting owner before any enrollment rows enter
    // its namespace. Startup correctly refuses orphan rows without this config.
    drop(
        common::host_storage::open(
            path,
            f.trust.clone(),
            policy(limits.checkpoint_period_seconds),
            RealVerifier::default(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    );
    let mut store = common::host_storage::open_enrollment(path, limits).unwrap();
    registry::enroll(&mut store, f, d, 130).unwrap();
}
/// The host registry as the slot builder sees it: (pseudonym, device) pairs that are NOT
/// current (revoked or removed). Every other device is current.
#[derive(Default)]
struct Registry {
    revoked: Mutex<Vec<(String, [u8; 32])>>,
    asked: Mutex<Vec<(String, [u8; 32])>>,
}
impl cblc::current_device::CurrentDevices for Registry {
    fn is_current(&self, pseudonym: &str, device: &[u8; 32]) -> Result<bool, Error> {
        self.asked
            .lock()
            .unwrap()
            .push((pseudonym.to_owned(), *device));
        Ok(!self
            .revoked
            .lock()
            .unwrap()
            .iter()
            .any(|(p, d)| p == pseudonym && d == device))
    }
}
fn prepare<C: Fn() -> u64>(
    source: &mut EnrollmentService<C>,
    f: &Fixture,
    epoch: u64,
    owner: Arc<Current>,
) -> Result<PendingCheckpoint, Error> {
    prepare_with(source, f, epoch, owner, &Registry::default())
}
fn prepare_with<C: Fn() -> u64>(
    source: &mut EnrollmentService<C>,
    f: &Fixture,
    epoch: u64,
    owner: Arc<Current>,
    devices: &Registry,
) -> Result<PendingCheckpoint, Error> {
    source.prepare_checkpoint(
        ExpectedAdmission {
            trust: &f.trust,
            policy_epoch: epoch,
            passport_policy_digest: &common::encoded(10),
        },
        owner,
        devices,
    )
}
/// A delegation as long as its admission grant (decision (b)): grant, root authorization and
/// delegation all end at `until`, independent of the device session's lease.
fn grant_long(f: &Fixture, member: u8, device: &SigningKey, until: u64) -> AccountingDelegation {
    let mut d = delegation(f);
    d.admission = f.grant_until(member, device, until);
    d.authorization = f.authorize_until(member, device, until);
    d.expires_at = until;
    resign(&mut d, device);
    d
}
fn pending_key(slot: u64) -> Vec<u8> {
    let mut key = b"enrollment/pending/".to_vec();
    key.extend_from_slice(&slot.to_be_bytes());
    key
}
fn slot_key(slot: u64) -> Vec<u8> {
    let mut key = vec![3];
    key.extend_from_slice(&8_u64.to_be_bytes());
    key.extend_from_slice(&slot.to_be_bytes());
    key
}
fn read(path: &Path, community: &str, key: &[u8]) -> Option<serde_json::Value> {
    let mut store = cssr::LibsqlStore::local(path, community).unwrap();
    let mut tx = cssr::Storage::transaction(&mut store).unwrap();
    let value = tx
        .get(key)
        .unwrap()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap());
    tx.rollback().unwrap();
    value
}

#[test]
fn genuine_sql_prepare_install_lost_ack_reopen_and_identical_retry_keep_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let limits = registry::config(&f);
    populate(&path, &f, &d, limits.clone());
    let now = Arc::new(AtomicU64::new(130));
    let owner = current(&f, &d);
    let mut source = producer(&path, &f, limits.clone(), now.clone());
    let mut ledger = target(&path, &f, 100, 9, now.clone());
    let pending = prepare(&mut source, &f, 1, owner.clone()).unwrap();
    let bytes = serde_json::to_vec(pending.publication()).unwrap();
    assert_eq!(pending.publication().not_before, 100);
    assert_eq!(pending.publication().expires_at, 200);
    assert!(source.checkpoint(1).unwrap().is_none());
    let installed = ledger
        .publish_pending_checkpoint(pending, owner.clone())
        .unwrap();
    assert_eq!(serde_json::to_vec(installed.publication()).unwrap(), bytes);
    drop(installed);
    drop(ledger);
    drop(source); // actual commit, lost acknowledgment
    now.store(131, Ordering::Release);
    let mut source = producer(&path, &f, limits, now.clone());
    let mut ledger = target(&path, &f, 100, 9, now.clone());
    assert!(source.checkpoint(1).unwrap().is_none());
    let retry = prepare(&mut source, &f, 1, owner.clone()).unwrap();
    assert_eq!(serde_json::to_vec(retry.publication()).unwrap(), bytes);
    let installed = ledger.publish_pending_checkpoint(retry, owner).unwrap();
    assert_eq!(
        serde_json::to_vec(&source.acknowledge(installed).unwrap()).unwrap(),
        bytes
    );
    assert_eq!(
        serde_json::to_vec(&source.checkpoint(1).unwrap().unwrap()).unwrap(),
        bytes
    );
    assert_eq!(
        read(&path, &f.trust.community_id, b"clock").unwrap(),
        serde_json::json!(131)
    );
    assert!(read(&path, &f.trust.community_id, &slot_key(1)).is_some());
}

#[test]
fn only_whole_slot_delegations_enter_tree_and_empty_eligible_roster_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let limits = registry::config(&f);
    let mut short = d.clone();
    short.admission = f.grant(8, &f.device);
    short.authorization = f.authorize(8, &f.device);
    short.expires_at = 199;
    resign(&mut short, &f.device);
    populate(&path, &f, &d, limits.clone());
    populate(&path, &f, &short, limits.clone());
    let now = Arc::new(AtomicU64::new(130));
    let mut source = producer(&path, &f, limits, now);
    let pending = prepare(&mut source, &f, 1, current(&f, &d)).unwrap();
    assert_eq!(pending.publication().delegations.len(), 1);
    assert_eq!(
        pending.publication().delegations[0].entry.member_id,
        d.admission.member_id
    );
    let empty = dir.path().join("short.db");
    let limits = registry::config(&f);
    populate(&empty, &f, &short, limits.clone());
    let mut source = producer(&empty, &f, limits, Arc::new(AtomicU64::new(130)));
    assert!(matches!(
        prepare(&mut source, &f, 1, current(&f, &d)),
        Err(Error::Admission)
    ));
    assert!(read(&empty, &f.trust.community_id, &pending_key(1)).is_none());
}

#[test]
fn a_slot_long_after_enrollment_keeps_the_member_with_a_grant_long_delegation() {
    // Fixture scale: slots of 100 s, a lease-bound delegation would have ended ~15 min after
    // enrollment. Enrolled at 130; the slot built 20 min later still holds the member, because
    // the delegation lives as long as the admission grant.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = grant_long(&f, 7, &f.device, 2400);
    let limits = registry::config(&f);
    populate(&path, &f, &d, limits.clone());
    let now = Arc::new(AtomicU64::new(130 + 20 * 60));
    let mut source = producer(&path, &f, limits, now);
    let registry = Registry::default();
    let pending = prepare_with(&mut source, &f, 1, current(&f, &d), &registry).unwrap();
    assert_eq!(pending.publication().slot, 13);
    assert_eq!(pending.publication().delegations.len(), 1);
    assert_eq!(
        pending.publication().delegations[0].entry.member_id,
        d.admission.member_id
    );
    // The registry was asked only what the roster entry already names: pseudonym and device.
    assert_eq!(
        *registry.asked.lock().unwrap(),
        vec![(d.admission.pseudonym.clone(), f.device.verifying_key().to_bytes())]
    );
}

#[test]
fn a_revoked_devices_unexpired_delegation_is_excluded_from_the_next_slot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let kept = grant_long(&f, 7, &f.device, 2400);
    let lost = SigningKey::from_bytes(&[5; 32]);
    let revoked = grant_long(&f, 8, &lost, 2400);
    let limits = registry::config(&f);
    populate(&path, &f, &kept, limits.clone());
    populate(&path, &f, &revoked, limits.clone());
    let now = Arc::new(AtomicU64::new(130));
    let mut source = producer(&path, &f, limits.clone(), now.clone());
    let registry = Registry::default();
    let first = prepare_with(&mut source, &f, 1, current(&f, &kept), &registry).unwrap();
    assert_eq!(first.publication().delegations.len(), 2);
    drop(first);
    // The device is revoked in the registry. Its delegation is still unexpired, yet the next
    // slot leaves it out; the frozen slot 1 keeps its original bytes.
    registry
        .revoked
        .lock()
        .unwrap()
        .push((revoked.admission.pseudonym.clone(), lost.verifying_key().to_bytes()));
    now.store(230, Ordering::Release);
    let next = prepare_with(&mut source, &f, 1, current(&f, &kept), &registry).unwrap();
    assert_eq!(next.publication().slot, 2);
    assert_eq!(next.publication().delegations.len(), 1);
    assert_eq!(
        next.publication().delegations[0].entry.member_id,
        kept.admission.member_id
    );
    // A roster whose only delegation is revoked is empty and refuses, as before.
    let empty = dir.path().join("revoked.db");
    populate(&empty, &f, &revoked, limits.clone());
    let mut source = producer(&empty, &f, limits, Arc::new(AtomicU64::new(130)));
    assert!(matches!(
        prepare_with(&mut source, &f, 1, current(&f, &kept), &registry),
        Err(Error::Admission)
    ));
    assert!(read(&empty, &f.trust.community_id, &pending_key(1)).is_none());
}

#[test]
fn frozen_recovery_is_historical_only_and_obsolete_unrenewed_new_slot_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("common.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let limits = registry::config(&f);
    populate(&path, &f, &d, limits.clone());
    let now = Arc::new(AtomicU64::new(130));
    let owner = current(&f, &d);
    let mut source = producer(&path, &f, limits, now.clone());
    let original = prepare(&mut source, &f, 1, owner.clone()).unwrap();
    let bytes = serde_json::to_vec(original.publication()).unwrap();
    drop(original);
    let mut renewed = d.clone();
    renewed.admission.policy_epoch = 2;
    f.resign_grant(&mut renewed.admission);
    resign(&mut renewed, &f.device);
    *owner.delegation.lock().unwrap() = renewed;
    owner.epoch.store(2, Ordering::Release);
    now.store(131, Ordering::Release);
    let recovered = prepare(&mut source, &f, 2, owner.clone()).unwrap();
    assert_eq!(serde_json::to_vec(recovered.publication()).unwrap(), bytes);
    // Public bytes remain the original epoch, not a current verification seal.
    assert_eq!(
        recovered.publication().delegations[0]
            .delegation
            .admission
            .policy_epoch,
        1
    );
    assert!(matches!(
        verify_delegation(
            &recovered.publication().delegations[0].delegation,
            ExpectedAdmission {
                trust: &f.trust,
                policy_epoch: 2,
                passport_policy_digest: &common::encoded(10)
            },
            131
        ),
        Err(Error::Admission)
    ));
    let mut ledger = target(&path, &f, 100, 9, now.clone());
    let installed = ledger
        .publish_pending_checkpoint(recovered, owner.clone())
        .unwrap();
    source.acknowledge(installed).unwrap();
    now.store(210, Ordering::Release);
    assert!(matches!(
        prepare(&mut source, &f, 2, owner),
        Err(Error::Admission)
    ));
    assert!(read(&path, &f.trust.community_id, &pending_key(2)).is_none());
    assert_eq!(
        serde_json::to_vec(&source.checkpoint(1).unwrap().unwrap()).unwrap(),
        bytes
    );
}

#[test]
fn forwarding_retains_source_owner_and_current_epoch_refusal_prevents_actual_install() {
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
    owner.epoch.store(2, Ordering::Release);
    // Different fresh target owner cannot replace the retained source owner.
    let mut ledger = target(&path, &f, 100, 9, now);
    assert!(matches!(
        ledger.publish_pending_checkpoint(pending, current(&f, &d)),
        Err(Error::Admission)
    ));
    assert!(read(&path, &f.trust.community_id, &slot_key(1)).is_none());
    assert_eq!(
        read(&path, &f.trust.community_id, b"clock").unwrap(),
        serde_json::json!(130)
    );
}
