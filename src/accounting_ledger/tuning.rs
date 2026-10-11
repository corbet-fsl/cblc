//! Trusted, durable live tuning. This is never a member-controlled endpoint.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WaitingPeriodTuning {
    pub revision: u64,
    pub seconds: u64,
    pub policy_digest: [u8; 32],
    pub state_policy_digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredConfig {
    format: String,
    community_id: String,
    admission_policy_digest: String,
    pub(super) policy_keys: Vec<u8>,
    pub policy: AccountLedgerPolicy,
    proof_scope: AccountProofScope,
    operator_key: [u8; 32],
    pub tuning_revision: u64,
}

pub(super) fn config_bytes(
    trust: &AdmissionTrust,
    policy: &AccountLedgerPolicy,
    proof_scope: &AccountProofScope,
    operator_key: [u8; 32],
    tuning_revision: u64,
) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&StoredConfig {
        format: "cblc.account.database.v5".into(),
        community_id: trust.community_id.clone(),
        admission_policy_digest: trust.policy_digest.clone(),
        policy_keys: trust.policy_keys.to_cbor(),
        policy: policy.clone(),
        proof_scope: proof_scope.clone(),
        operator_key,
        tuning_revision,
    })
    .map_err(|_| Error::InvalidInput)
}

pub(super) fn check_config(
    transaction: &mut Transaction<'_>,
    expected: &[u8],
) -> Result<(), Error> {
    let stored: Vec<u8> = transaction.get(b"config")?.ok_or(Error::Storage)?;
    if stored != expected {
        return Err(Error::PolicyMismatch);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn check_epoch_config(frozen: &[u8], current: &[u8]) -> Result<(), Error> {
    check_config_successor(None, frozen, current)
}

pub(super) fn check_epoch_config_in(
    transaction: &mut Transaction<'_>,
    frozen: &[u8],
    current: &[u8],
) -> Result<(), Error> {
    check_config_successor(Some(transaction), frozen, current)
}

fn check_config_successor(
    transaction: Option<&mut Transaction<'_>>,
    frozen: &[u8],
    current: &[u8],
) -> Result<(), Error> {
    let mut prior: StoredConfig = serde_json::from_slice(frozen).map_err(|_| Error::Storage)?;
    let active: StoredConfig = serde_json::from_slice(current).map_err(|_| Error::Storage)?;
    prior.policy.validate()?;
    active.policy.validate()?;
    if active.tuning_revision > MAX_INTEGER || active.tuning_revision < prior.tuning_revision {
        return Err(Error::PolicyMismatch);
    }
    if active.tuning_revision > prior.tuning_revision {
        prior.tuning_revision = active.tuning_revision;
        prior.policy.account.abandon_after = active.policy.account.abandon_after;
    }
    if prior.policy_keys != active.policy_keys {
        let transaction = transaction.ok_or(Error::PolicyMismatch)?;
        let previous = csgn::KeyRing::from_cbor(&prior.policy_keys).map_err(|_| Error::Storage)?;
        let active_keys =
            csgn::KeyRing::from_cbor(&active.policy_keys).map_err(|_| Error::Storage)?;
        admission_keys::check_successor(transaction, &previous, &active_keys)?;
        prior.policy_keys = active.policy_keys.clone();
    }
    if serde_json::to_vec(&prior).map_err(|_| Error::Storage)? != current {
        return Err(Error::PolicyMismatch);
    }
    Ok(())
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Current local snapshot. Call `reload_policy` to observe another writer's update.
    pub fn account_policy(&self) -> &AccountPolicy {
        &self.policy.account
    }

    pub fn waiting_period(&self) -> Result<WaitingPeriodTuning, Error> {
        Ok(WaitingPeriodTuning {
            revision: self.tuning_revision,
            seconds: self.policy.account.abandon_after,
            policy_digest: self.policy_digest,
            state_policy_digest: self.policy.account.state_digest(&self.community)?,
        })
    }

    /// Change only the waiting period for future outgoing reservations. The
    /// current circuit commits each existing slot's original deadline. No
    /// account, balance, admission counter or event history is reset here.
    ///
    /// The host must authorize this operation separately from member requests.
    /// `expected_revision` prevents concurrent operators from overwriting a
    /// newer decision. New writes on stale ledger handles fail closed.
    /// A late or uncertain commit may have stored the new revision even though
    /// this returns an error. Call `reload_policy` to reconcile before deciding
    /// another update; never assume the attempted tuning was rolled back.
    pub fn update_waiting_period(
        &mut self,
        expected_revision: u64,
        seconds: u64,
        clock: impl Fn() -> u64,
    ) -> Result<WaitingPeriodTuning, Error> {
        let clock = observed_clock(self.observed_time.clone(), clock);
        if expected_revision != self.tuning_revision {
            return Err(Error::PolicyMismatch);
        }
        let mut policy = self.policy.clone();
        policy.account.abandon_after = seconds;
        policy.account.validate()?;
        let revision = expected_revision
            .checked_add(1)
            .filter(|v| *v <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        let digest = policy.account.digest(&self.community)?;
        let config = config_bytes(
            &self.trust,
            &policy,
            &self.proof_scope,
            self.operator.verifying_key().to_bytes(),
            revision,
        )?;
        let before = clock();
        check_time(before, 0)?;
        let mut transaction = self.connection.transaction()?;
        check_config(&mut transaction, &self.config)?;
        let now = clock();
        check_time(now, clock_floor(&mut transaction)?.max(before))?;
        if now < policy.account.policy_valid_from || now >= policy.account.policy_valid_until {
            return Err(Error::Expired);
        }
        policy.account.reservation_deadline(now)?;
        transaction.put(b"config", &config)?;
        // reservation_deadline(now) above proved this subtraction is positive.
        // Recheck the actual atomic decision after all host writes complete.
        transaction.commit_before(&CommitDeadline::new(
            &clock,
            now,
            policy.account.policy_valid_until - policy.account.abandon_after,
        ))?;
        self.config = config;
        self.policy = policy;
        self.policy_digest = digest;
        self.tuning_revision = revision;
        self.waiting_period()
    }

    /// Refresh after original waiting tuning or a durably verified CSGN signer
    /// successor. Every other policy, proof and database setting stays exact.
    pub fn reload_policy(&mut self) -> Result<WaitingPeriodTuning, Error> {
        let mut transaction = self.connection.transaction()?;
        let config: Vec<u8> = transaction.get(b"config")?.ok_or(Error::Storage)?;
        let stored: StoredConfig = serde_json::from_slice(&config).map_err(|_| Error::Storage)?;
        let mut trust = self.trust.clone();
        if stored.policy_keys != trust.policy_keys.to_cbor() {
            trust.policy_keys =
                csgn::KeyRing::from_cbor(&stored.policy_keys).map_err(|_| Error::Storage)?;
            admission_keys::check_successor(
                &mut transaction,
                &self.trust.policy_keys,
                &trust.policy_keys,
            )?;
        }
        let bootstrap = admission_keys::open(&mut transaction, &trust.policy_keys, false, None)?;
        if bootstrap != self.admission_bootstrap {
            return Err(Error::PolicyMismatch);
        }
        transaction.rollback()?;
        let mut policy = self.policy.clone();
        policy.account.abandon_after = stored.policy.account.abandon_after;
        policy.account.validate()?;
        if stored.tuning_revision < self.tuning_revision
            || stored.tuning_revision > MAX_INTEGER
            || config
                != config_bytes(
                    &trust,
                    &policy,
                    &self.proof_scope,
                    self.operator.verifying_key().to_bytes(),
                    stored.tuning_revision,
                )?
        {
            return Err(Error::PolicyMismatch);
        }
        self.policy_digest = policy.account.digest(&self.community)?;
        self.trust = trust;
        self.policy = policy;
        self.tuning_revision = stored.tuning_revision;
        self.config = config;
        self.waiting_period()
    }
}

#[cfg(test)]
#[path = "../../tests/internal/epoch_tuning.rs"]
mod epoch_tests;
