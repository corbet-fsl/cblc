//! Original immutable enrollment registry in the caller's atomic store.
use super::{
    AccountingDelegation, ExpectedAdmission,
    publication::{EnrollmentDelegation, EnrollmentEntry},
    verify_delegation,
};
use crate::{
    Error,
    storage::{AccountStorage, CommitAuthority, CommitDeadline, authority::AuthorityScope},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const CONFIG: &[u8] = b"enrollment/config";
const START: &[u8] = b"enrollment/member/";
const END: &[u8] = b"enrollment/member0";

/// Explicit original deployment limits and independently selected identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentConfig {
    pub community_id: String,
    pub policy_digest: String,
    pub operator_public_key: [u8; 32],
    pub checkpoint_period_seconds: u64,
    pub max_members: u32,
    pub max_retained_slots: u32,
    pub max_publication_bytes: u64,
}
impl EnrollmentConfig {
    /// Validate configuration without inferring any publication authority.
    pub fn validate(&self) -> Result<(), Error> {
        if !czkp::scope(&self.community_id)
            || self.policy_digest.len() != 43
            || self.checkpoint_period_seconds == 0
            || self.checkpoint_period_seconds > czkp::MAX_INTEGER
            || !(1..=65536).contains(&self.max_members)
            || self.max_retained_slots == 0
            || self.max_retained_slots > 65536
            || self.max_publication_bytes == 0
            || self.max_publication_bytes > 64 * 1024 * 1024
        {
            return Err(Error::InvalidInput);
        }
        czkp::decode::<32>(&self.policy_digest)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.operator_public_key)
            .map_err(|_| Error::InvalidInput)?;
        if key.is_weak() {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

/// Complete public authority retained for renewal and later exact verification.
/// A stored row is not a current verification seal.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredEnrollment {
    record: EnrollmentDelegation,
}
impl StoredEnrollment {
    /// Exact stored authority, still requiring the current owner verifier.
    pub fn delegation(&self) -> &AccountingDelegation {
        &self.record.delegation
    }
    /// Original immutable account header and current renewal interval.
    pub fn entry(&self) -> &EnrollmentEntry {
        &self.record.entry
    }
}

/// Caller-owned immutable registry. No SQL connections or wallet material are
/// opened here. Member writes require an actual per-command host authority.
pub struct EnrollmentStore {
    pub(super) storage: Box<dyn AccountStorage>,
    scope: AuthorityScope,
    pub(super) config: EnrollmentConfig,
}
impl EnrollmentStore {
    /// Bind a real caller transaction port and explicit publisher configuration.
    /// Construction does not write or install an account/enrollment root.
    pub fn new<S: AccountStorage + 'static>(
        storage: S,
        config: EnrollmentConfig,
    ) -> Result<Self, Error> {
        config.validate()?;
        let (storage, scope) = AuthorityScope::wrap(storage);
        Ok(Self {
            storage,
            scope,
            config,
        })
    }
    /// Authenticate and atomically retain the original immutable account binding.
    /// The exact host capability is captured before taking the writer; the same
    /// root Scope checks it at the original logical storage decision.
    pub fn enroll(
        &mut self,
        delegation: &AccountingDelegation,
        expected: ExpectedAdmission<'_>,
        authority: Arc<dyn CommitAuthority>,
        clock: impl Fn() -> u64,
    ) -> Result<EnrollmentEntry, Error> {
        if expected.trust.community_id != self.config.community_id
            || expected.trust.policy_digest != self.config.policy_digest
        {
            return Err(Error::Admission);
        }
        let _scope = self.scope.enter(authority)?;
        let mut tx = self.storage.transaction()?;
        let now = clock();
        let floor: Option<u64> = tx.get(b"clock")?;
        if floor.is_some_and(|floor| now < floor) {
            return Err(Error::ClockRollback);
        }
        let verified = verify_delegation(delegation, expected, now)?;
        let record = EnrollmentDelegation::from_verified(&verified);
        let entry = record.entry.clone();
        let stored: Option<EnrollmentConfig> = tx.get(CONFIG)?;
        if stored.as_ref().is_some_and(|stored| stored != &self.config) {
            return Err(Error::PolicyMismatch);
        }
        let mut key = START.to_vec();
        key.extend_from_slice(entry.member_id.as_bytes());
        let previous: Option<StoredEnrollment> = tx.get(&key)?;
        if stored.is_none() {
            let rows = tx.current_range::<StoredEnrollment>(START, END, 1)?;
            if !rows.is_empty() {
                return Err(Error::Storage);
            }
        }
        if let Some(previous) = previous {
            previous.record.validate()?;
            if previous.entry().member_id != entry.member_id
                || previous.entry().account_key != entry.account_key
                || previous.entry().secret_hash != entry.secret_hash
            {
                return Err(Error::PolicyMismatch);
            }
            let same = serde_json::to_vec(&previous.record).map_err(|_| Error::Storage)?
                == serde_json::to_vec(&record).map_err(|_| Error::Storage)?;
            if !same && entry.issued_at <= previous.entry().issued_at {
                return Err(Error::Replay);
            }
        } else {
            let rows =
                tx.current_range::<StoredEnrollment>(START, END, self.config.max_members + 1)?;
            if rows.len() >= self.config.max_members as usize {
                return Err(Error::Capacity);
            }
            for (key, row) in rows {
                row.record.validate()?;
                if key.get(START.len()..) != Some(row.entry().member_id.as_bytes()) {
                    return Err(Error::Storage);
                }
            }
        }
        if stored.is_none() {
            tx.put(CONFIG, &self.config)?;
        }
        tx.put(&key, &StoredEnrollment { record })?;
        let deadline = CommitDeadline::new(&clock, now, verified.valid_until());
        tx.commit_before(&deadline)?;
        Ok(entry)
    }
    /// Read every original current row. Shape validation precedes any caller's
    /// expiry omission; old unexpired epochs must be reverified, never dropped.
    pub fn records(&mut self) -> Result<Vec<StoredEnrollment>, Error> {
        let mut tx = self.storage.transaction()?;
        let stored: Option<EnrollmentConfig> = tx.get(CONFIG)?;
        if stored.as_ref().is_some_and(|stored| stored != &self.config) {
            return Err(Error::PolicyMismatch);
        }
        let rows = tx.current_range::<StoredEnrollment>(START, END, self.config.max_members + 1)?;
        if rows.len() > self.config.max_members as usize || (stored.is_none() && !rows.is_empty()) {
            return Err(Error::Storage);
        }
        let mut result = Vec::with_capacity(rows.len());
        for (key, row) in rows {
            row.record.validate()?;
            if key.get(START.len()..) != Some(row.entry().member_id.as_bytes()) {
                return Err(Error::Storage);
            }
            result.push(row);
        }
        tx.rollback()?;
        Ok(result)
    }
    /// Independently bound publisher identity, period and original byte limits.
    pub fn config(&self) -> &EnrollmentConfig {
        &self.config
    }
}
