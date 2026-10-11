//! Bounded decoding of the original completed-spend fields on the native owner.
use super::*;
use cpns::server::Change;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    request: AccountRequest,
    acceptance: AccountAcceptance,
    update: crate::extensions::ExtendedUpdate,
}

impl<V: AccountProofVerifier, C: Fn() -> u64> AccountService<V, C> {
    /// Consume no new spend: verify the original exact completed receipt and
    /// native proof. The application independently supplies the pending change
    /// and retains current member authority through its eventual pin CAS.
    pub fn verify_completed_pin_change(
        &mut self,
        change: &Change<'_>,
        evidence: &[u8],
    ) -> Result<crate::pins::VerifiedPinChange, Error> {
        if evidence.is_empty() || evidence.len() > self.max_request_bytes {
            return Err(Error::InvalidInput);
        }
        let evidence: Evidence =
            serde_json::from_slice(evidence).map_err(|_| Error::InvalidInput)?;
        self.ledger.reload_policy()?;
        self.ledger.verify_completed_pin_change(
            change,
            &crate::pins::SpentChange {
                request: evidence.request,
                acceptance: evidence.acceptance,
                update: evidence.update,
            },
            &self.clock,
        )
    }
}
