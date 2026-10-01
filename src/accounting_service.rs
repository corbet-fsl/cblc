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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub enum AccountServiceRequest {
    Apply {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: Box<AccountRequest>,
    },
    ApplyExtended {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: Box<AccountRequest>,
        update: crate::extensions::ExtendedUpdate,
    },
    Obligations {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: AccountStatusRequest,
    },
    Status {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: AccountStatusRequest,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "action",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum AccountServiceResponse {
    Apply(AccountAcceptance),
    Status(AccountStatusResponse),
    ApplyExtended {
        acceptance: AccountAcceptance,
        certificate: crate::extensions::StateCertificate,
    },
    Obligations(crate::obligations::ObligationsResponse),
}

/// Hosts supply their own trusted clock, HTTP/onion transport and access control
/// for local administration. Settlement ingress is not a member operation.
pub struct AccountService<V: AccountProofVerifier, C: Fn() -> u64> {
    ledger: AccountLedger<V>,
    clock: C,
    max_request_bytes: usize,
    extension_issuer: Option<cssr::certificate::CertificateIssuer>,
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
            extension_issuer: None,
        })
    }

    /// Operator-owned certificate key, authenticated by the extension manifest.
    pub fn with_extension_issuer(mut self, issuer: cssr::certificate::CertificateIssuer) -> Self {
        self.extension_issuer = Some(issuer);
        self
    }

    /// Recover composition ownership without duplicating or recreating state.
    pub fn into_ledger(self) -> AccountLedger<V> {
        self.ledger
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

    /// Door composition supplies the canonical pseudonym from its freshly
    /// authenticated membership, independently of the member's request body.
    pub fn handle_for_member(
        &mut self,
        pseudonym: &[u8; 48],
        request: AccountServiceRequest,
    ) -> Result<AccountServiceResponse, Error> {
        let grant = match &request {
            AccountServiceRequest::Apply { grant, .. }
            | AccountServiceRequest::ApplyExtended { grant, .. }
            | AccountServiceRequest::Obligations { grant, .. }
            | AccountServiceRequest::Status { grant, .. } => grant,
        };
        if grant.pseudonym != data_encoding::HEXLOWER.encode(pseudonym) {
            return Err(Error::Admission);
        }
        self.handle(request)
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
            AccountServiceRequest::ApplyExtended {
                grant,
                authorization,
                request,
                update,
            } => {
                let issuer = self
                    .extension_issuer
                    .as_ref()
                    .ok_or(Error::UnsupportedCapability)?;
                let acceptance = self.ledger.apply_extended(
                    &grant,
                    &authorization,
                    &request,
                    &update,
                    &self.clock,
                )?;
                let certificate = self.ledger.certify_extended(&acceptance, issuer)?;
                Ok(AccountServiceResponse::ApplyExtended {
                    acceptance,
                    certificate,
                })
            }
            AccountServiceRequest::Obligations {
                grant,
                authorization,
                request,
            } => self
                .ledger
                .authenticated_obligations(&grant, &authorization, &request, &self.clock)
                .map(AccountServiceResponse::Obligations),
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
