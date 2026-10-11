//! Real native verification followed by minimal durable operational staging.
use super::*;
use crate::settlement::{SettlementStatus, SettlementSubmission, StagedSettlement, deposit_digest};

fn syntax(
    deposit: &crate::extensions::Deposit,
    community: &[u8; 32],
    delay: u64,
    now: u64,
) -> Result<(), Error> {
    if &deposit.community != community
        || [
            deposit.recipient,
            deposit.nullifier,
            deposit.authorization_nullifier,
            deposit.obligation,
        ]
        .contains(&[0; 32])
        || deposit.release_epoch == 0
        || deposit.release_epoch > now / delay
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

pub(super) fn facts(
    tx: &mut Transaction<'_>,
    settlement: &Settlement,
) -> Result<Vec<(Vec<u8>, VerifiedDepositFact)>, Error> {
    let rows: Vec<(Vec<u8>, VerifiedDepositFact)> = tx.current_range(
        FACT_PREFIX,
        &prefix_end(FACT_PREFIX)?,
        settlement.config.pending_capacity + 1,
    )?;
    let count: u32 = tx.get(COUNT)?.ok_or(Error::Storage)?;
    if rows.len() > settlement.config.pending_capacity as usize {
        return Err(Error::Capacity);
    }
    if rows.len() != count as usize {
        return Err(Error::Storage);
    }
    let mut nullifiers = std::collections::BTreeSet::new();
    let mut authorizations = std::collections::BTreeSet::new();
    for (stored_key, fact) in &rows {
        if fact.format != "cblc.settlement.verified-fact.v1"
            || fact.binding != settlement.binding
            || fact.eligible_epoch == 0
            || fact.eligible_epoch > MAX_INTEGER
            || fact.deposit.community != settlement.community
            || fact.deposit.release_epoch == 0
            || fact.deposit.release_epoch > MAX_INTEGER
            || fact
                .eligible_epoch
                .checked_mul(settlement.config.period_seconds)
                .is_none_or(|cut| cut > MAX_INTEGER)
            || stored_key != &fact_key(fact.eligible_epoch, &fact.deposit.nullifier)
            || [
                fact.deposit.community,
                fact.deposit.recipient,
                fact.deposit.nullifier,
                fact.deposit.authorization_nullifier,
                fact.deposit.obligation,
            ]
            .contains(&[0; 32])
            || !nullifiers.insert(fact.deposit.nullifier)
            || !authorizations.insert(fact.deposit.authorization_nullifier)
        {
            return Err(Error::Storage);
        }
    }
    Ok(rows)
}

fn existing(
    tx: &mut Transaction<'_>,
    settlement: &Settlement,
    deposit: &crate::extensions::Deposit,
    digest: [u8; 32],
) -> Result<Option<SettlementStatus>, Error> {
    let rows = facts(tx, settlement)?;
    for (_, fact) in &rows {
        if fact.deposit.nullifier == deposit.nullifier {
            if fact.deposit != *deposit {
                return Err(Error::Replay);
            }
            return Ok(Some(SettlementStatus::Staged(StagedSettlement {
                deposit_digest: digest,
                eligible_epoch: fact.eligible_epoch,
            })));
        }
        if fact.deposit.authorization_nullifier == deposit.authorization_nullifier {
            return Err(Error::Replay);
        }
    }
    if let Some(prior) = tx.get::<[u8; 32]>(&key(8, &[&deposit.nullifier]))? {
        if prior != digest {
            return Err(Error::Replay);
        }
        return Ok(Some(SettlementStatus::Applied {
            deposit_digest: digest,
        }));
    }
    if tx
        .get::<bool>(&key(9, &[&deposit.authorization_nullifier]))?
        .is_some()
    {
        return Err(Error::Replay);
    }
    tx.get::<Frontier>(&key(1, &[&deposit.recipient]))?
        .ok_or(Error::Admission)?;
    let count: u8 = tx.get(&key(10, &[&deposit.recipient]))?.unwrap_or(0);
    let pending = rows
        .iter()
        .filter(|(_, fact)| fact.deposit.recipient == deposit.recipient)
        .count();
    if usize::from(count) + pending >= 64
        || rows.len() >= settlement.config.pending_capacity as usize
    {
        return Err(Error::Capacity);
    }
    Ok(None)
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Anonymous native ingress. Staging preserves only original verified
    /// operational facts, never raw proofs or a holder/session/source link.
    /// The daily owner must apply ALL due facts with G2 in one atomic commit.
    pub fn stage_settlement(
        &mut self,
        submission: &SettlementSubmission,
        clock: impl Fn() -> u64,
    ) -> Result<SettlementStatus, Error> {
        let settlement = self
            .settlement
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        if submission.proof.is_empty()
            || submission.proof.len() > self.policy.max_proof_bytes
            || submission.token_proof.len() > cmbl::settlement::MAX_PROOF_BYTES
            || submission.operation == [0; 16]
        {
            return Err(Error::InvalidInput);
        }
        let clock = observed_clock(self.observed_time.clone(), clock);
        let now = clock();
        check_time(now, 0)?;
        syntax(
            &submission.deposit,
            &self.community,
            extensions.policy.deposit_delay_seconds,
            now,
        )?;
        let digest = deposit_digest(&submission.deposit)?;
        let mut tx = self.connection.transaction()?;
        let locked = clock();
        check_time(locked, now.max(clock_floor(&mut tx)?))?;
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, Some(extensions))?;
        anchor(&mut tx, settlement)?;
        if let Some(prior) = existing(&mut tx, settlement, &submission.deposit, digest)? {
            // This is a query of the exact already-verified durable fact/effect,
            // not acceptance of the newly presented proof or an expired token.
            tx.rollback()?;
            let returned = clock();
            check_time(returned, locked)?;
            return Ok(prior);
        }
        tx.rollback()?;
        let expected = cmbl::settlement::Request {
            deposit: digest,
            operation: submission.operation,
        };
        let permit = settlement
            .verifier
            .verify(&submission.token_proof, &expected, milliseconds(locked)?)
            .map_err(crypto_error)?;
        if permit.context() != settlement.context
            || permit.deposit() != digest
            || permit.epoch() != settlement.config.epoch.epoch
            || permit.valid_until() != settlement.config.epoch.valid_until
        {
            return Err(Error::Admission);
        }
        extensions.budget.check(&submission.deposit.recipient)?;
        extensions.verifier.verify_anonymous(
            &ExtensionStatement::Deposit {
                policy: extensions.policy.clone(),
                deposit: submission.deposit.clone(),
            },
            &submission.proof,
        )?;
        let completed = clock();
        check_time(completed, locked)?;
        let mut tx = self.connection.transaction()?;
        let decision = clock();
        check_time(decision, completed.max(clock_floor(&mut tx)?))?;
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, Some(extensions))?;
        anchor(&mut tx, settlement)?;
        if decision / settlement.config.period_seconds != permit.epoch()
            || milliseconds(decision)? >= permit.valid_until()
        {
            return Err(Error::Expired);
        }
        if let Some(prior) = existing(&mut tx, settlement, &submission.deposit, digest)? {
            tx.rollback()?;
            let returned = clock();
            check_time(returned, decision)?;
            return Ok(prior);
        }
        let token_key = scoped_key(TOKEN_PREFIX, &[&permit.token()]);
        if tx.get::<[u8; 32]>(&token_key)?.is_some() {
            return Err(Error::Replay);
        }
        let eligible_epoch = (decision / settlement.config.period_seconds)
            .checked_add(1)
            .filter(|n| *n <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        let cut = eligible_epoch
            .checked_mul(settlement.config.period_seconds)
            .filter(|n| *n <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        let fact = VerifiedDepositFact {
            format: "cblc.settlement.verified-fact.v1".into(),
            deposit: submission.deposit.clone(),
            binding: settlement.binding,
            eligible_epoch,
        };
        let count: u32 = tx.get(COUNT)?.ok_or(Error::Storage)?;
        tx.put(
            &fact_key(eligible_epoch, &submission.deposit.nullifier),
            &fact,
        )?;
        tx.put(COUNT, &count.checked_add(1).ok_or(Error::Capacity)?)?;
        tx.put(&token_key, &digest)?;
        // A proof/commit cannot cross the original token epoch or selected cut.
        // The host resamples at its actual serialized commit decision.
        let deadline = cut.min(permit.valid_until() / 1000);
        tx.commit_before(&CommitDeadline::new(&clock, decision, deadline))?;
        let returned = clock();
        if check_time(returned, decision).is_err() || returned >= deadline {
            return Err(Error::Storage);
        }
        Ok(SettlementStatus::Staged(StagedSettlement {
            deposit_digest: digest,
            eligible_epoch,
        }))
    }
}
