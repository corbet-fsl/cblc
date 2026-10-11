//! Install only the original configured common producer's opaque preparation.
use super::*;
use crate::enrollment::{InstalledCheckpoint, PendingCheckpoint};

impl<V: AccountProofVerifier> AccountLedger<V> {
    pub(crate) fn install_pending_checkpoint(
        &mut self,
        pending: PendingCheckpoint,
        clock: impl Fn() -> u64,
    ) -> Result<InstalledCheckpoint, Error> {
        let clock = observed_clock(self.observed_time.clone(), clock);
        let mut tx = self.connection.transaction()?;
        let now = clock();
        let floor: Option<u64> = tx.get(b"clock")?;
        check_time(now, floor.unwrap_or(0))?;
        check_config(&mut tx, &self.config)?;
        pending.validate_install(
            &self.trust.community_id,
            &self.trust.policy_digest,
            &self.operator.verifying_key().to_bytes(),
            self.policy.checkpoint_period_seconds,
            now,
        )?;
        let publication = pending.publication();
        // Do not install an earlier slot even if an older trusted host path
        // admitted a later checkpoint without the newer durable clock record.
        let next = publication.slot.checked_add(1).ok_or(Error::InvalidInput)?;
        let later = tx.current_range::<Vec<u8>>(&key(3, &[&next.to_be_bytes()]), &[4], 1)?;
        if !later.is_empty() {
            return Err(Error::Replay);
        }
        let slot_key = key(3, &[&publication.slot.to_be_bytes()]);
        let prior: Option<Vec<u8>> = tx.get(&slot_key)?;
        let mut marker_key = b"enrollment/installed/".to_vec();
        marker_key.extend_from_slice(&publication.slot.to_be_bytes());
        let identity = pending.correspondence()?;
        let marker: Option<([u8; 32], [u8; 32])> = tx.get(&marker_key)?;
        if marker.is_some() && prior.is_none() {
            return Err(Error::Storage);
        }
        if marker.is_some_and(|marker| marker != identity) {
            return Err(Error::PolicyMismatch);
        }
        if let Some(prior) = prior {
            if prior.as_slice() != publication.root {
                return Err(Error::PolicyMismatch);
            }
        } else {
            tx.put(&slot_key, &publication.root.to_vec())?;
        }
        // A genuine current-slot producer seal may attach correspondence to an
        // identical legacy trusted root. Absence alone never supplies authority,
        // changes the root, or renews the original interval.
        tx.put(&marker_key, &identity)?;
        tx.commit_before(&CommitDeadline::new(&clock, now, publication.expires_at))?;
        Ok(pending.installed())
    }
}
