//! Host-only original signer continuity on the same native account owner.
use super::*;
use crate::accounting_ledger::{AdmissionKeyReconciliation, AdmissionKeyState};

impl<V: AccountProofVerifier, C: Fn() -> u64> AccountService<V, C> {
    /// Retain exact installed state through the same ledger's original live
    /// signature checks and atomic transaction. Never a member wire command.
    pub fn reconcile_admission_keys(
        &mut self,
        request: AdmissionKeyReconciliation,
    ) -> Result<AdmissionKeyState, Error> {
        self.ledger.reconcile_admission_keys(request, &self.clock)
    }
}
