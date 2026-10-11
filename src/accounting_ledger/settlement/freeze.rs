//! One atomic daily effects/G2 boundary. The prepared transaction is an overlay
//! only; rollback precedes encryption, and every due fact/frontier is rechecked
//! before the one final commit. No committed chunks or minimum batch.
use super::super::{extensions, record_epoch};
use super::ingress::facts;
use super::*;
use crate::{extensions::PendingObligation, settlement::deposit_digest};

fn due(
    tx: &mut Transaction<'_>,
    settlement: &Settlement,
    epoch: u64,
) -> Result<Vec<(Vec<u8>, VerifiedDepositFact)>, Error> {
    Ok(facts(tx, settlement)?
        .into_iter()
        .filter(|(_, fact)| fact.eligible_epoch <= epoch)
        .collect())
}

fn apply_facts(
    tx: &mut Transaction<'_>,
    rows: &[(Vec<u8>, VerifiedDepositFact)],
) -> Result<(), Error> {
    for (_, fact) in rows {
        let deposit = &fact.deposit;
        // Staging and an already-applied marker cannot coexist: effect and
        // fact deletion share one original transaction, including retries.
        if !extensions::check_deposit(tx, deposit)? {
            return Err(Error::Storage);
        }
        let previous = crate::extensions::inbox(tx, &deposit.recipient)?;
        let next = crate::extensions::advance(&previous, deposit)?;
        let count_key = key(10, &[&deposit.recipient]);
        let count: u8 = tx.get(&count_key)?.unwrap_or(0);
        tx.put(&count_key, &(count + 1))?;
        tx.put(&key(8, &[&deposit.nullifier]), &deposit_digest(deposit)?)?;
        tx.put(&key(9, &[&deposit.authorization_nullifier]), &true)?;
        tx.put(
            &key(6, &[&deposit.recipient, &next.root]),
            &PendingObligation {
                previous,
                commitment: deposit.obligation,
            },
        )?;
        tx.put(&key(5, &[&deposit.recipient]), &next)?;
    }
    Ok(())
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Apply ALL verified facts due at this cut with complete original G2.
    /// Zero/one/many deposits use the same original proof and extension policy;
    /// no padding or synthetic event. The production host supplies the original
    /// daily period and holds Policy authority through publication forwarding.
    pub fn publish_daily_settlement(
        &mut self,
        policy_epoch: u64,
        period_seconds: u64,
        clock: impl Fn() -> u64,
    ) -> Result<record_epoch::RecordEpochPublication, Error> {
        let settlement = self
            .settlement
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        if policy_epoch == 0
            || policy_epoch > MAX_INTEGER
            || policy_epoch != settlement.config.policy_epoch
            || period_seconds != settlement.config.period_seconds
        {
            return Err(Error::PolicyMismatch);
        }
        extensions.verifier.require_record_epoch()?;
        let clock = observed_clock(self.observed_time.clone(), clock);
        let before = clock();
        check_time(before, 0)?;
        let mut tx = self.connection.transaction()?;
        let now = clock();
        check_time(now, before.max(clock_floor(&mut tx)?))?;
        let epoch = now / period_seconds;
        if epoch == 0 {
            return Err(Error::InvalidInput);
        }
        let end = epoch
            .checked_add(1)
            .and_then(|n| n.checked_mul(period_seconds))
            .filter(|n| *n <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, Some(extensions))?;
        anchor(&mut tx, settlement)?;
        let scope = extensions.verifier.scope();
        let inputs = record_epoch::EpochInputs {
            community: self.community,
            issuer_key: self.operator.verifying_key().to_bytes(),
            policy_epoch,
            epoch,
            period_seconds,
            now,
            configuration: &self.config,
            extension_configuration: &extensions.config,
            proof_scope: &scope,
        };
        let selected = due(&mut tx, settlement, epoch)?;
        if let Some(prior) = record_epoch::existing_in(&mut tx, &inputs)? {
            if !selected.is_empty() {
                return Err(Error::Replay);
            }
            tx.rollback()?;
            let returned = clock();
            check_time(returned, now)?;
            prior.descriptor().check_time(returned)?;
            return Ok(prior);
        }
        apply_facts(&mut tx, &selected)?;
        let frozen = record_epoch::prepare_in(&mut tx, &inputs, &clock)?;
        tx.rollback()?;
        let issuer = cssr::certificate::RecordIssuer::new(&self.operator.to_bytes());
        let published = frozen.encrypt(&issuer)?;
        let completed = clock();
        check_time(completed, now)?;
        published.descriptor().check_time(completed)?;
        let mut tx = self.connection.transaction()?;
        let decision = clock();
        check_time(decision, completed.max(clock_floor(&mut tx)?))?;
        if decision / period_seconds != epoch {
            return Err(Error::Expired);
        }
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, Some(extensions))?;
        anchor(&mut tx, settlement)?;
        let current = due(&mut tx, settlement, epoch)?;
        if let Some(prior) = record_epoch::existing_in(&mut tx, &inputs)? {
            if !current.is_empty() {
                return Err(Error::Replay);
            }
            // A competing cut must have applied our exact prepared facts.
            for (_, fact) in &selected {
                let digest: Option<[u8; 32]> = tx.get(&key(8, &[&fact.deposit.nullifier]))?;
                if digest != Some(deposit_digest(&fact.deposit)?) {
                    return Err(Error::Storage);
                }
            }
            tx.rollback()?;
            let returned = clock();
            check_time(returned, decision)?;
            prior.descriptor().check_time(returned)?;
            return Ok(prior);
        }
        if current != selected {
            return Err(Error::Replay);
        }
        apply_facts(&mut tx, &selected)?;
        record_epoch::install_in(&mut tx, &frozen, &published, decision)?;
        let count: u32 = tx.get(COUNT)?.ok_or(Error::Storage)?;
        let remaining = count
            .checked_sub(selected.len() as u32)
            .ok_or(Error::Storage)?;
        for (stored_key, _) in &selected {
            tx.delete(stored_key)?;
        }
        tx.put(COUNT, &remaining)?;
        // Effects/replay, every lineage/common object/anchor and deletion share
        // this ONE transaction and the original actual commit-time clock cut.
        tx.commit_before(&CommitDeadline::new(&clock, decision, end))?;
        let returned = clock();
        if check_time(returned, decision).is_err() || returned >= end {
            return Err(Error::Storage);
        }
        Ok(published)
    }
}
