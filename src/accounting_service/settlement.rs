//! The same native service owns issuance, anonymous verification and daily cut.
use super::*;
use crate::settlement::{SettlementPassRequest, SettlementStatus, SettlementSubmission};
use crate::storage::CommitAuthority;
use std::sync::Arc;

impl<V: AccountProofVerifier, C: Fn() -> u64> AccountService<V, C> {
    /// Trusted Policy-currentness reconciliation on the SAME native service.
    /// The supplied actual owner survives cancellation and final writer checks.
    pub fn reconcile_daily_settlement(
        &mut self,
        config: crate::settlement::SettlementConfig,
        provisioned_key: &[u8],
        incarnation: String,
        authority: Arc<dyn CommitAuthority>,
    ) -> Result<cmbl::settlement::Epoch, Error> {
        self.ledger.reload_policy()?;
        self.ledger.reconcile_daily_settlement(
            config,
            provisioned_key,
            incarnation,
            authority,
            &self.clock,
        )
    }
    /// Production member issuance retains and rechecks the actual facade's
    /// current member/device/Policy owners inside the original native writer.
    pub fn issue_settlement_pass_authorized(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &SettlementPassRequest,
        authority: Arc<dyn CommitAuthority>,
    ) -> Result<Vec<u8>, Error> {
        let _scope = self.ledger.authority.enter(authority)?;
        self.issue_settlement_pass(grant, authorization, request)
    }
    /// Trusted common epoch renewal only, never a member/anonymous key import.
    pub fn activate_daily_settlement(
        &mut self,
        config: crate::settlement::SettlementConfig,
        provisioned_key: &[u8],
        incarnation: String,
    ) -> Result<cmbl::settlement::Epoch, Error> {
        self.ledger.reload_policy()?;
        self.ledger
            .activate_daily_settlement(config, provisioned_key, incarnation, &self.clock)
    }
    /// Original authenticated member/device/Policy leases must remain held by
    /// the admitting facade through cancellation, as for other account work.
    pub fn issue_settlement_pass(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &SettlementPassRequest,
    ) -> Result<Vec<u8>, Error> {
        self.ledger.reload_policy()?;
        self.ledger
            .issue_settlement_pass(grant, authorization, request, &self.clock)
    }

    /// Native anonymous ingress, without any member session or named DTO. The
    /// configured daily owner applies its durable verified facts at the G2 cut.
    pub fn stage_settlement(
        &mut self,
        submission: &SettlementSubmission,
    ) -> Result<SettlementStatus, Error> {
        self.ledger.reload_policy()?;
        self.ledger.stage_settlement(submission, &self.clock)
    }
}
