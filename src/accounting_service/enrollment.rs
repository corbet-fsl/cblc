//! Original host-only checkpoint installation, absent from all member DTOs.
use super::*;
use crate::enrollment::{InstalledCheckpoint, PendingCheckpoint};
use crate::storage::CommitAuthority;
use std::sync::Arc;

struct Current {
    source: Arc<dyn CommitAuthority>,
    target: Arc<dyn CommitAuthority>,
}
impl CommitAuthority for Current {
    fn check(&self, now: u64) -> Result<(), Error> {
        self.source.check(now)?;
        if !Arc::ptr_eq(&self.source, &self.target) {
            self.target.check(now)?;
        }
        Ok(())
    }
    fn boundary_crossed(&self, observed: u64, now: u64) -> Result<bool, Error> {
        Ok(self.source.boundary_crossed(observed, now)?
            || (!Arc::ptr_eq(&self.source, &self.target)
                && self.target.boundary_crossed(observed, now)?))
    }
}

impl<V: AccountProofVerifier, C: Fn() -> u64> AccountService<V, C> {
    /// Consume the configured producer's exact durable common preparation.
    /// A plain parsed publication or a member-selected root cannot call this
    /// owner path; expired or mismatched original slots refuse atomically.
    pub fn publish_pending_checkpoint(
        &mut self,
        pending: PendingCheckpoint,
        authority: Arc<dyn CommitAuthority>,
    ) -> Result<InstalledCheckpoint, Error> {
        // Reuse the same captured Arc where source/target share a Policy owner.
        // Never reacquire its outer mutex while pending retains that guard.
        let _scope = self.ledger.authority.enter(Arc::new(Current {
            source: pending.source_authority(),
            target: authority,
        }))?;
        self.ledger.reload_policy()?;
        self.ledger.install_pending_checkpoint(pending, &self.clock)
    }
}
