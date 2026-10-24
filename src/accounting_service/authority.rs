//! Retain current application authority throughout the original member command.
use super::*;
use crate::storage::CommitAuthority;
use std::sync::Arc;

impl<V: AccountProofVerifier, C: Fn() -> u64> AccountService<V, C> {
    /// The queued owner must capture the real member/session/Policy leases in
    /// `authority`. Every commit rechecks them inside the host writer barrier;
    /// caller cancellation does not release them while native work continues.
    pub fn handle_for_member_authorized(
        &mut self,
        pseudonym: &[u8; 48],
        request: AccountServiceRequest,
        authority: Arc<dyn CommitAuthority>,
    ) -> Result<AccountServiceResponse, Error> {
        let _scope = self.ledger.authority.enter(authority)?;
        self.handle_for_member(pseudonym, request)
    }

    /// Like `handle`, for a host that retains the member authority (including its device
    /// lineage) across the command. Updates are refused without it.
    pub fn handle_authorized(
        &mut self,
        request: AccountServiceRequest,
        authority: Arc<dyn CommitAuthority>,
    ) -> Result<AccountServiceResponse, Error> {
        let _scope = self.ledger.authority.enter(authority)?;
        self.handle(request)
    }
}
