//! Original common checkpoint publisher, using the caller's actual atomic port.
use super::*;
use crate::Error;
use crate::storage::{CommitAuthority, CommitDeadline, Transaction};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

mod pending;
pub use pending::{InstalledCheckpoint, PendingCheckpoint};

/// Original configured common publisher. The host must retain its actual
/// current Policy/configuration owners over preparation and forwarding.
/// Reuse a captured Arc when owners coincide; never acquire the same outer
/// Policy mutex again while a pending/installed command retains its guard.
pub struct EnrollmentService<C: Fn() -> u64> {
    store: EnrollmentStore,
    operator: SigningKey,
    clock: C,
    observed: Arc<AtomicU64>,
}
fn clock<C: Fn() -> u64>(observed: Arc<AtomicU64>, clock: &C) -> impl Fn() -> u64 + '_ {
    move || {
        let now = clock();
        if now == 0 || now > czkp::MAX_INTEGER || now < observed.fetch_max(now, Ordering::AcqRel) {
            0
        } else {
            now
        }
    }
}
fn config(tx: &mut Transaction<'_>, expected: &EnrollmentConfig) -> Result<(), Error> {
    let stored: Option<EnrollmentConfig> = tx.get(b"enrollment/config")?;
    if stored.as_ref() != Some(expected) {
        return Err(Error::PolicyMismatch);
    }
    Ok(())
}
fn time(tx: &mut Transaction<'_>, now: u64) -> Result<(), Error> {
    let floor: Option<u64> = tx.get(b"clock")?;
    if now == 0 || now > czkp::MAX_INTEGER || floor.is_some_and(|floor| now < floor) {
        return Err(Error::ClockRollback);
    }
    Ok(())
}
impl<C: Fn() -> u64> EnrollmentService<C> {
    /// Actual immutable publisher configuration; this observation is not an
    /// installation capability or a current Policy verdict.
    pub fn configuration(&self) -> &EnrollmentConfig {
        &self.store.config
    }

    /// Configure the actual original detached operator, not a signing callback.
    pub fn new(store: EnrollmentStore, operator: SigningKey, clock: C) -> Result<Self, Error> {
        if operator.verifying_key().to_bytes() != store.config.operator_public_key {
            return Err(Error::PolicyMismatch);
        }
        Ok(Self {
            store,
            operator,
            clock,
            observed: Arc::new(AtomicU64::new(0)),
        })
    }
    /// Intake under the genuine current host pseudonym and root storage owner.
    /// No caller-supplied member ID can substitute for that authenticated subject.
    pub fn enroll_for_member(
        &mut self,
        pseudonym: &[u8; 48],
        delegation: &AccountingDelegation,
        expected: ExpectedAdmission<'_>,
        authority: Arc<dyn CommitAuthority>,
    ) -> Result<EnrollmentEntry, Error> {
        if crate::admission::member_id(pseudonym) != delegation.admission.member_id {
            return Err(Error::Admission);
        }
        self.store.enroll(
            delegation,
            expected,
            authority,
            clock(self.observed.clone(), &self.clock),
        )
    }
    /// Freeze the original complete current slot. Old unexpired policy epochs
    /// refuse the whole build; expired rows are retained but never enter the tree.
    /// Exact retained same-slot bytes keep their original end, never a renewed one.
    /// The captured owner must bind these SAME current Policy/epoch/cohort
    /// expectations at the actual commit; sampled input alone is not authority.
    pub fn prepare_checkpoint(
        &mut self,
        expected: ExpectedAdmission<'_>,
        authority: Arc<dyn CommitAuthority>,
    ) -> Result<PendingCheckpoint, Error> {
        if expected.trust.community_id != self.store.config.community_id
            || expected.trust.policy_digest != self.store.config.policy_digest
        {
            return Err(Error::Admission);
        }
        let clock = clock(self.observed.clone(), &self.clock);
        let _scope = self.store.scope.enter(authority.clone())?;
        let mut tx = self.store.storage.transaction()?;
        let now = clock();
        time(&mut tx, now)?;
        config(&mut tx, &self.store.config)?;
        let period = self.store.config.checkpoint_period_seconds;
        let slot = now / period;
        let end = slot
            .checked_add(1)
            .and_then(|slot| slot.checked_mul(period))
            .filter(|end| *end <= czkp::MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        let prior: Option<pending::Frozen> = tx.get(&pending::key(slot))?;
        let frozen = if let Some(prior) = prior {
            pending::validate(&self.store.config, &prior.publication)?;
            pending::authenticate_frozen(&prior, expected.trust, now)?;
            prior
        } else {
            let rows = tx.current_range::<StoredEnrollment>(
                b"enrollment/member/",
                b"enrollment/member0",
                self.store.config.max_members + 1,
            )?;
            if rows.len() > self.store.config.max_members as usize {
                return Err(Error::Capacity);
            }
            let mut verified = Vec::new();
            for (key, row) in rows {
                row.record.validate()?;
                if key.get(b"enrollment/member/".len()..) != Some(row.entry().member_id.as_bytes())
                {
                    return Err(Error::Storage);
                }
                if row.entry().expires_at <= now {
                    continue;
                }
                let value = verify_delegation(
                    row.delegation(),
                    ExpectedAdmission {
                        trust: expected.trust,
                        policy_epoch: expected.policy_epoch,
                        passport_policy_digest: expected.passport_policy_digest,
                    },
                    now,
                )?;
                if value.valid_until() >= end {
                    verified.push(value);
                }
            }
            let tree = EnrollmentTree::from_verified(&verified)?;
            let mut publication = EnrollmentPublication {
                version: 1,
                domain: ENROLLMENT_DOMAIN.into(),
                community_id: self.store.config.community_id.clone(),
                policy_digest: self.store.config.policy_digest.clone(),
                slot,
                not_before: slot * period,
                expires_at: end,
                root: tree.root(),
                delegations: verified
                    .iter()
                    .map(EnrollmentDelegation::from_verified)
                    .collect(),
                signature: String::new(),
            };
            publication
                .delegations
                .sort_by(|a, b| a.entry.member_id.cmp(&b.entry.member_id));
            publication.signature = BASE64URL_NOPAD
                .encode(&self.operator.sign(&publication.signing_bytes()?).to_bytes());
            let frozen = pending::Frozen {
                publication,
                installed: false,
                checked_at: now,
                policy_epoch: expected.policy_epoch,
                passport_policy_digest: expected.passport_policy_digest.into(),
            };
            pending::persist(&mut tx, &self.store.config, &frozen)?;
            frozen
        };
        tx.commit_before(&CommitDeadline::new(&clock, now, end))?;
        Ok(PendingCheckpoint::new(
            self.store.config.clone(),
            frozen,
            authority,
        ))
    }
    /// Mark installed only after the actual accounting owner's acknowledgment.
    /// Lost acknowledgment uses the original same-slot prepare/install retry.
    /// Finish/drop all command Arc handles before later Policy signing awaits;
    /// the returned plain publication retains no opaque owner guards.
    pub fn acknowledge(
        &mut self,
        installed: InstalledCheckpoint,
    ) -> Result<EnrollmentPublication, Error> {
        let clock = clock(self.observed.clone(), &self.clock);
        let publication = installed.publication();
        let _scope = self.store.scope.enter(installed.0.source_authority())?;
        if !installed.0.same_config(&self.store.config) {
            return Err(Error::PolicyMismatch);
        }
        installed.0.validate_install(
            &self.store.config.community_id,
            &self.store.config.policy_digest,
            &self.store.config.operator_public_key,
            self.store.config.checkpoint_period_seconds,
            clock(),
        )?;
        let mut tx = self.store.storage.transaction()?;
        let now = clock();
        time(&mut tx, now)?;
        config(&mut tx, &self.store.config)?;
        let prior: pending::Frozen = tx
            .get(&pending::key(publication.slot))?
            .ok_or(Error::Storage)?;
        if pending::correspondence(&self.store.config, &prior)? != installed.0.correspondence()? {
            return Err(Error::PolicyMismatch);
        }
        let mut acknowledged = prior;
        acknowledged.installed = true;
        tx.put(&pending::key(publication.slot), &acknowledged)?;
        tx.commit_before(&CommitDeadline::new(&clock, now, publication.expires_at))?;
        // Returning only public data drops both opaque receipts and their
        // retained source guard before a host's later Policy publication awaits.
        Ok(publication.clone())
    }
    /// Only exact already-installed historical objects are available. A missing
    /// or uninstalled slot never rebuilds or installs a root from today's roster.
    pub fn checkpoint(&mut self, slot: u64) -> Result<Option<EnrollmentPublication>, Error> {
        let clock = clock(self.observed.clone(), &self.clock);
        let mut tx = self.store.storage.transaction()?;
        let now = clock();
        time(&mut tx, now)?;
        if slot > now / self.store.config.checkpoint_period_seconds {
            return Err(Error::InvalidInput);
        }
        let stored: Option<EnrollmentConfig> = tx.get(b"enrollment/config")?;
        if let Some(stored) = stored {
            if stored != self.store.config {
                return Err(Error::PolicyMismatch);
            }
        } else {
            // Fresh construction intentionally writes no configuration. Only
            // an actually empty source namespace can mean absent history;
            // missing configuration alongside ANY retained row is corruption.
            if !tx
                .current_range::<serde_json::Value>(b"enrollment/", b"enrollment0", 1)?
                .is_empty()
            {
                return Err(Error::Storage);
            }
            tx.rollback_before(&CommitDeadline::new(&clock, now, czkp::MAX_INTEGER + 1))?;
            return Ok(None);
        }
        let prior: Option<pending::Frozen> = tx.get(&pending::key(slot))?;
        let result = if let Some(prior) = prior {
            pending::validate(&self.store.config, &prior.publication)?;
            prior.installed.then_some(prior.publication)
        } else {
            None
        };
        // Historical public bytes do not renew member/account authority. Still
        // retain the original durable observed clock on this host operation.
        tx.commit_before(&CommitDeadline::new(&clock, now, czkp::MAX_INTEGER + 1))?;
        Ok(result)
    }
}
