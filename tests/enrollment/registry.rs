use super::*;
use cblc::storage::{AccountStorage, CommitAuthority, MemoryStore};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

// This current-owner cut checks the real signed delegation under independent
// epoch/trust expectations. It is not a proof verifier or native acceptance.
struct Current {
    delegation: AccountingDelegation,
    trust: cblc::admission::AdmissionTrust,
    epoch: AtomicU64,
    checked: AtomicU64,
}
impl CommitAuthority for Current {
    fn check(&self, observed: u64) -> Result<(), Error> {
        self.checked.store(observed, Ordering::Release);
        verify_delegation(
            &self.delegation,
            ExpectedAdmission {
                trust: &self.trust,
                policy_epoch: self.epoch.load(Ordering::Acquire),
                passport_policy_digest: &common::encoded(10),
            },
            observed,
        )
        .map(|_| ())
    }
}
fn authority(f: &Fixture, d: &AccountingDelegation) -> Arc<Current> {
    Arc::new(Current {
        delegation: d.clone(),
        trust: f.trust.clone(),
        epoch: AtomicU64::new(1),
        checked: AtomicU64::new(0),
    })
}
pub(super) fn config(f: &Fixture) -> EnrollmentConfig {
    EnrollmentConfig {
        community_id: f.trust.community_id.clone(),
        policy_digest: f.trust.policy_digest.clone(),
        operator_public_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        checkpoint_period_seconds: 100,
        max_members: 2,
        max_retained_slots: 2,
        max_publication_bytes: 65536,
    }
}
pub(super) fn enroll(
    store: &mut EnrollmentStore,
    f: &Fixture,
    d: &AccountingDelegation,
    now: u64,
) -> Result<EnrollmentEntry, Error> {
    store.enroll(
        d,
        ExpectedAdmission {
            trust: &f.trust,
            policy_epoch: 1,
            passport_policy_digest: &common::encoded(10),
        },
        authority(f, d),
        || now,
    )
}
fn another(f: &Fixture, member: u8) -> AccountingDelegation {
    let mut d = delegation(f);
    d.admission = f.grant(member, &f.device);
    d.authorization = f.authorize(member, &f.device);
    resign(&mut d, &f.device);
    d
}

#[test]
fn sqlite_reopen_exact_retry_and_strict_renewal_preserve_the_immutable_binding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enrollment.db");
    let f = Fixture::new();
    let d = delegation(&f);
    let mut store = common::host_storage::open_enrollment(&path, config(&f)).unwrap();
    let entry = enroll(&mut store, &f, &d, 130).unwrap();
    drop(store);
    let mut store = common::host_storage::open_enrollment(&path, config(&f)).unwrap();
    assert_eq!(enroll(&mut store, &f, &d, 131).unwrap(), entry);
    let mut renewal = d.clone();
    renewal.issued_at = 132;
    resign(&mut renewal, &f.device);
    let latest = enroll(&mut store, &f, &renewal, 133).unwrap();
    assert_eq!(latest.account_key, entry.account_key);
    assert_eq!(latest.secret_hash, entry.secret_hash);
    assert_ne!(latest.delegation_digest, entry.delegation_digest);
    assert!(matches!(
        enroll(&mut store, &f, &d, 134),
        Err(Error::Replay)
    ));
    let mut conflict = renewal.clone();
    conflict.expires_at -= 1;
    resign(&mut conflict, &f.device);
    assert!(matches!(
        enroll(&mut store, &f, &conflict, 134),
        Err(Error::Replay)
    ));
    for key in [false, true] {
        let mut changed = renewal.clone();
        changed.issued_at = 135;
        if key {
            let p256 = p256::ecdsa::SigningKey::from_bytes((&[5; 32]).into()).unwrap();
            changed.account_public_key =
                HEX.encode(&p256.verifying_key().to_sec1_point(false).as_bytes()[1..]);
        } else {
            changed.state_secret_commitment = HEX.encode(&[5; 32]);
        }
        resign(&mut changed, &f.device);
        assert!(matches!(
            enroll(&mut store, &f, &changed, 136),
            Err(Error::PolicyMismatch)
        ));
    }
    drop(store);
    let mut store = common::host_storage::open_enrollment(&path, config(&f)).unwrap();
    let rows = store.records().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].entry(), &latest);
    assert!(matches!(
        enroll(&mut store, &f, &renewal, 132),
        Err(Error::ClockRollback)
    ));
}

#[test]
fn changed_current_epoch_at_the_actual_decision_rolls_back_rows_config_and_clock() {
    let f = Fixture::new();
    let d = delegation(&f);
    let mut durable = MemoryStore::default();
    let mut store = EnrollmentStore::new(durable.clone(), config(&f)).unwrap();
    let current = authority(&f, &d);
    let calls = std::cell::Cell::new(0);
    let clock = || {
        let call = calls.get();
        calls.set(call + 1);
        if call == 1 {
            current.epoch.store(2, Ordering::Release);
        }
        130
    };
    assert!(matches!(
        store.enroll(
            &d,
            ExpectedAdmission {
                trust: &f.trust,
                policy_epoch: 1,
                passport_policy_digest: &common::encoded(10)
            },
            current.clone(),
            clock
        ),
        Err(Error::Admission)
    ));
    assert_eq!(current.checked.load(Ordering::Acquire), 130);
    assert!(store.records().unwrap().is_empty());
    let mut tx = durable.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"clock").unwrap(), None);
    assert!(
        tx.get::<EnrollmentConfig>(b"enrollment/config")
            .unwrap()
            .is_none()
    );
    tx.rollback().unwrap();
    enroll(&mut store, &f, &d, 130).unwrap();
}

#[test]
fn expiry_at_the_real_commit_cut_rolls_back_and_same_signed_input_can_retry() {
    let f = Fixture::new();
    let d = delegation(&f);
    let mut store = EnrollmentStore::new(MemoryStore::default(), config(&f)).unwrap();
    let calls = std::cell::Cell::new(0);
    let clock = || {
        let n = calls.get();
        calls.set(n + 1);
        if n == 0 { 130 } else { 600 }
    };
    assert!(matches!(
        store.enroll(
            &d,
            ExpectedAdmission {
                trust: &f.trust,
                policy_epoch: 1,
                passport_policy_digest: &common::encoded(10)
            },
            authority(&f, &d),
            clock
        ),
        Err(Error::Expired)
    ));
    assert!(store.records().unwrap().is_empty());
    enroll(&mut store, &f, &d, 130).unwrap();
}

#[test]
fn member_bound_refuses_overflow_and_keeps_expired_rows_for_real_renewal() {
    let f = Fixture::new();
    let mut limits = config(&f);
    limits.max_members = 1;
    let mut store = EnrollmentStore::new(MemoryStore::default(), limits).unwrap();
    let d = delegation(&f);
    enroll(&mut store, &f, &d, 130).unwrap();
    assert!(matches!(
        enroll(&mut store, &f, &another(&f, 8), 131),
        Err(Error::Capacity)
    ));
    assert_eq!(store.records().unwrap().len(), 1);
    let rows = store.records().unwrap();
    assert!(matches!(
        verify_delegation(
            rows[0].delegation(),
            ExpectedAdmission {
                trust: &f.trust,
                policy_epoch: 2,
                passport_policy_digest: &common::encoded(10)
            },
            131
        ),
        Err(Error::Admission)
    ));
    // Raw retention is not a fresh seal: the actual current owner refuses it.
    let rows = store.records().unwrap();
    assert!(matches!(
        check(rows[0].delegation(), &f, 600),
        Err(Error::Admission)
    ));
    let mut renewal = d;
    renewal.issued_at = 601;
    renewal.expires_at = 800;
    resign(&mut renewal, &f.device);
    enroll(&mut store, &f, &renewal, 602).unwrap();
    assert_eq!(store.records().unwrap()[0].entry().issued_at, 601);
}

#[test]
fn orphan_or_malformed_rows_refuse_without_repair_and_configuration_is_exact() {
    let f = Fixture::new();
    let d = delegation(&f);
    for corruption in 0..3 {
        let mut durable = MemoryStore::default();
        let mut store = EnrollmentStore::new(durable.clone(), config(&f)).unwrap();
        enroll(&mut store, &f, &d, 130).unwrap();
        let mut tx = durable.transaction().unwrap();
        if corruption == 1 {
            tx.delete(b"enrollment/config").unwrap();
        } else {
            let mut key = b"enrollment/member/".to_vec();
            key.extend_from_slice(d.admission.member_id.as_bytes());
            let corrupt = if corruption == 0 {
                serde_json::json!({"record":{"entry":{},"delegation":d}})
            } else {
                // Even a complete expired row must pass original protocol
                // shape validation before a later publisher may omit it.
                let mut bad = d.clone();
                bad.version = 2;
                let mut entry = EnrollmentEntry::from_verified(&check(&d, &f, 130).unwrap());
                entry.delegation_digest = HEX.encode(&bad.digest().unwrap());
                serde_json::json!({"record":{"entry":entry,"delegation":bad}})
            };
            tx.put(&key, &corrupt).unwrap();
        }
        tx.commit().unwrap();
        assert!(store.records().is_err());
        assert!(enroll(&mut store, &f, &d, 131).is_err());
    }
    let durable = MemoryStore::default();
    let mut store = EnrollmentStore::new(durable.clone(), config(&f)).unwrap();
    enroll(&mut store, &f, &d, 130).unwrap();
    let mut changed = config(&f);
    changed.checkpoint_period_seconds += 1;
    let mut other = EnrollmentStore::new(durable, changed).unwrap();
    assert!(matches!(other.records(), Err(Error::PolicyMismatch)));
    assert!(matches!(
        enroll(&mut other, &f, &d, 131),
        Err(Error::PolicyMismatch)
    ));
}

#[test]
fn genuine_signed_nonfield_commitment_refuses_before_immutable_registry_and_clock_write() {
    let f = Fixture::new();
    let mut d = delegation(&f);
    d.state_secret_commitment = HEX.encode(&[255; 32]);
    resign(&mut d, &f.device);
    // Crypto-only statements are broader than the concrete native leaf shape.
    check(&d, &f, 130).unwrap();
    let mut durable = MemoryStore::default();
    let mut store = EnrollmentStore::new(durable.clone(), config(&f)).unwrap();
    assert!(matches!(
        enroll(&mut store, &f, &d, 130),
        Err(Error::InvalidInput)
    ));
    assert!(store.records().unwrap().is_empty());
    let mut tx = durable.transaction().unwrap();
    assert!(
        tx.get::<EnrollmentConfig>(b"enrollment/config")
            .unwrap()
            .is_none()
    );
    assert!(tx.get::<u64>(b"clock").unwrap().is_none());
}
