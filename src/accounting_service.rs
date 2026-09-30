//! Transport-neutral authenticated account service and bounded real verifier.
//! Member requests never supply clocks, checkpoints, executable paths or policy.

use crate::{
    Error,
    accounting::{
        AccountAcceptance, AccountPolicy, AccountProofScope, AccountProofVerifier, AccountRequest,
        AccountStatement, AccountStatusRequest, AccountStatusResponse,
    },
    accounting_ledger::{AccountLedger, WaitingPeriodTuning},
    admission::{AdmissionGrant, DeviceAuthorization},
};
pub use cvfy::ProcessVerifierConfig;
use serde::{Deserialize, Serialize};
/// Adapter connecting policy public inputs to the generic proof verifier leaf.
#[derive(Clone)]
pub struct ProcessAccountVerifier(cvfy::ProcessVerifier);
impl ProcessAccountVerifier {
    pub fn new(config: ProcessVerifierConfig) -> Result<Self, Error> {
        Ok(Self(cvfy::ProcessVerifier::new(config)?))
    }
}
impl AccountProofVerifier for ProcessAccountVerifier {
    fn scope(&self) -> AccountProofScope {
        self.0.scope()
    }
    fn verify(&self, statement: &AccountStatement, proof: &[u8]) -> Result<(), Error> {
        self.0.verify(statement, proof)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub enum AccountServiceRequest {
    Apply {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: Box<AccountRequest>,
    },
    Status {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: AccountStatusRequest,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "action",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum AccountServiceResponse {
    Apply(AccountAcceptance),
    Status(AccountStatusResponse),
}

/// Hosts supply their own trusted clock, HTTP/onion transport and access control
/// for local administration. The member wire format exposes only apply/status.
pub struct AccountService<V: AccountProofVerifier, C: Fn() -> u64> {
    ledger: AccountLedger<V>,
    clock: C,
    max_request_bytes: usize,
}

impl<V: AccountProofVerifier, C: Fn() -> u64> AccountService<V, C> {
    pub fn new(
        ledger: AccountLedger<V>,
        clock: C,
        max_request_bytes: usize,
    ) -> Result<Self, Error> {
        if max_request_bytes == 0 || max_request_bytes > 16 * 1024 * 1024 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            ledger,
            clock,
            max_request_bytes,
        })
    }

    /// Enforce this bound while reading the transport body too, before allocation.
    pub fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    pub fn handle_json(&mut self, body: &[u8]) -> Result<Vec<u8>, Error> {
        if body.len() > self.max_request_bytes {
            return Err(Error::Capacity);
        }
        let request = serde_json::from_slice(body).map_err(|_| Error::InvalidInput)?;
        serde_json::to_vec(&self.handle(request)?).map_err(|_| Error::InvalidInput)
    }

    pub fn handle(
        &mut self,
        request: AccountServiceRequest,
    ) -> Result<AccountServiceResponse, Error> {
        // Observe another administrator's durable tuning before new requests.
        // The ledger still rechecks configuration at commit; racing changes fail closed.
        self.ledger.reload_policy()?;
        match request {
            AccountServiceRequest::Apply {
                grant,
                authorization,
                request,
            } => self
                .ledger
                .apply(&grant, &authorization, &request, &self.clock)
                .map(AccountServiceResponse::Apply),
            AccountServiceRequest::Status {
                grant,
                authorization,
                request,
            } => self
                .ledger
                .status(&grant, &authorization, &request, &self.clock)
                .map(AccountServiceResponse::Status),
        }
    }

    /// Public configuration only. The embedding authenticates its distribution.
    pub fn policy(&mut self) -> Result<(AccountPolicy, WaitingPeriodTuning), Error> {
        let tuning = self.ledger.reload_policy()?;
        Ok((self.ledger.account_policy().clone(), tuning))
    }

    /// Trusted local administration, absent from AccountServiceRequest.
    /// Independently verify the common enrollment tree before calling this.
    pub fn publish_verified_checkpoint(&mut self, slot: u64, root: [u8; 32]) -> Result<(), Error> {
        self.ledger.admit_checkpoint(slot, root)
    }

    /// Trusted local administration. The host must authorize the administrator.
    pub fn tune_waiting_period(
        &mut self,
        expected_revision: u64,
        seconds: u64,
    ) -> Result<WaitingPeriodTuning, Error> {
        self.ledger.reload_policy()?;
        self.ledger
            .update_waiting_period(expected_revision, seconds, &self.clock)
    }
}
