//! One live atomic catchup, never retroactive acceptance of an expired proof.
use super::*;

/// Host-held actual Policy target and original public continuity evidence.
/// Routing revisions are checked against CSGN, never trusted as authority.
/// There is no deserializer or member endpoint for this command.
pub struct AdmissionKeyReconciliation {
    /// Independently held current Policy ring and public transition revision.
    pub target: AdmissionKeyState,
    /// Original retained (revision, COSE bytes) in their original order.
    pub transitions: Vec<(u64, Vec<u8>)>,
}
impl AdmissionKeyReconciliation {
    pub(super) fn check_shape(&self) -> Result<(), Error> {
        if self.target.revision > MAX_INTEGER
            || self.transitions.len() > MAX_TRANSITIONS
            || serde_json::to_vec(&self.transitions)
                .map_err(|_| Error::InvalidInput)?
                .len()
                > MAX_HISTORY_BYTES
        {
            return Err(Error::Capacity);
        }
        let mut previous = 0;
        for (revision, proof) in &self.transitions {
            if *revision <= previous
                || (previous != 0 && Some(*revision) != previous.checked_add(1))
                || *revision > self.target.revision
                || proof.is_empty()
            {
                return Err(Error::PolicyMismatch);
            }
            previous = *revision;
        }
        Ok(())
    }
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Atomically reconcile this same native owner with the actual held Policy.
    /// Every missing proof is verified LIVE from the exact durable predecessor.
    /// An expired unseen tail leaves the whole native state unchanged. Only an
    /// exact already-observed prefix may remain historical; final target equality
    /// is mandatory. Late/unknown committed outcomes require reconciliation.
    pub fn reconcile_admission_keys(
        &mut self,
        request: AdmissionKeyReconciliation,
        clock: impl Fn() -> u64,
    ) -> Result<AdmissionKeyState, Error> {
        request.check_shape()?;
        let clock = observed_clock(self.observed_time.clone(), clock);
        let before = clock();
        check_time(before, 0)?;
        let mut tx = self.connection.transaction()?;
        check_config(&mut tx, &self.config)?;
        let (bootstrap, mut history, states) = read(&mut tx)?;
        if states.first() != self.admission_bootstrap.as_ref() {
            return Err(Error::PolicyMismatch);
        }
        let installed = states.last().ok_or(Error::Storage)?;
        if installed.policy_keys != self.trust.policy_keys
            || request.target.revision < installed.revision
        {
            return Err(Error::PolicyMismatch);
        }
        let mut next = installed.clone();
        let mut observed = before.max(clock_floor(&mut tx)?);
        let mut deadline = MAX_INTEGER;
        for (revision, proof) in &request.transitions {
            // An explicit deployment bootstrap did not derive its authority
            // from older transition bytes. They remain transport data only.
            if *revision <= bootstrap.revision {
                continue;
            }
            if *revision <= installed.revision {
                if !history
                    .transitions
                    .iter()
                    .any(|item| item.revision == *revision && item.proof == *proof)
                {
                    return Err(Error::PolicyMismatch);
                }
                continue;
            }
            if Some(*revision) != next.revision.checked_add(1) {
                return Err(Error::PolicyMismatch);
            }
            let now = clock();
            check_time(now, observed)?;
            let (successor, expires) = checked_transition(&next, proof, now)?;
            deadline = deadline.min(expires);
            observed = now;
            history.transitions.push(AcceptedTransition {
                revision: successor.revision,
                verified_at: now,
                proof: proof.clone(),
            });
            history.revision = successor.revision;
            bounded(&history)?;
            next = successor;
        }
        if next != request.target {
            return Err(Error::PolicyMismatch);
        }
        if next == *installed {
            tx.rollback()?;
            check_time(clock(), observed)?;
            return Ok(next);
        }
        let mut trust = self.trust.clone();
        trust.policy_keys = next.policy_keys.clone();
        let config = config_bytes(
            &trust,
            &self.policy,
            &self.proof_scope,
            self.operator.verifying_key().to_bytes(),
            self.tuning_revision,
        )?;
        tx.put(HISTORY, &history)?;
        tx.put(b"config", &config)?;
        tx.commit_before(&CommitDeadline::new(&clock, observed, deadline))?;
        let returned = clock();
        check_time(returned, observed).map_err(|_| Error::Storage)?;
        if returned >= deadline {
            return Err(Error::Storage);
        }
        self.trust = trust;
        self.config = config;
        Ok(next)
    }
}
