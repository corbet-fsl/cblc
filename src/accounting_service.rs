//! Transport-neutral authenticated account service and bounded real verifier.
//! Member requests never supply clocks, checkpoints, executable paths or policy.

use crate::artifacts::{AccountArtifacts, NativeVerifierOptions};
use crate::{
    Error,
    accounting::{
        AccountAcceptance, AccountPolicy, AccountProofScope, AccountProofVerifier, AccountRequest,
        AccountStatement, AccountStatusRequest, AccountStatusResponse,
    },
    accounting_ledger::{AccountLedger, WaitingPeriodTuning},
    admission::{AdmissionGrant, DeviceAuthorization},
};
use serde::{Deserialize, Serialize};
mod pin_change;
/// Adapter connecting policy public inputs to the generic proof verifier leaf.
#[derive(Clone)]
pub struct NativeAccountVerifier(cvfy::NativeVerifier);
impl NativeAccountVerifier {
    pub fn new(options: NativeVerifierOptions, artifacts: AccountArtifacts) -> Result<Self, Error> {
        Ok(Self(cvfy::NativeVerifier::new(artifacts.config(options))?))
    }
    /// Withdraw execution from this exact owned native verifier and its clones.
    pub fn cancellation(&self) -> cvfy::NativeCancellation {
        self.0.cancellation()
    }
}

/// Actual native process owners, retained before the service moves to its worker.
/// This only withdraws execution and cannot authorize or reset any operation.
pub struct NativeAccountCancellation {
    pub(crate) account: cvfy::NativeCancellation,
    pub(crate) extensions: Option<crate::verification::NativeExtensionCancellation>,
}
impl NativeAccountCancellation {
    pub fn cancel(&self) {
        self.account.cancel();
        if let Some(extensions) = &self.extensions {
            extensions.cancel();
        }
    }
}

impl<C: Fn() -> u64> AccountService<NativeAccountVerifier, C> {
    /// Cancel all native proof owners belonging to this same actual service.
    pub fn cancellation(&self) -> NativeAccountCancellation {
        self.ledger.native_cancellation()
    }
}
impl AccountProofVerifier for NativeAccountVerifier {
    fn scope(&self) -> AccountProofScope {
        self.0.scope()
    }
    fn verify(&self, statement: &AccountStatement, proof: &[u8]) -> Result<(), Error> {
        self.0
            .verify(&crate::prepared::account_inputs(statement)?, proof)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub enum AccountServiceRequest {
    RegisterRecordRecipient {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: crate::accounting_ledger::record_epoch::RecipientRequest,
    },
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
    /// Completion of the actual durable registration; never record authority.
    RecordRecipient {
        recipient_key: [u8; 32],
    },
    Apply(AccountAcceptance),
    Status(AccountStatusResponse),
    ApplyExtended {
        acceptance: AccountAcceptance,
        certificate: crate::extensions::StateCertificate,
        /// Original ancestry issued only in this acceptance's verified CAS.
        ancestry: Option<Box<crate::extensions::EpochAncestryCertificate>>,
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

    /// Immutable ledger scope for binding this service in the community host.
    pub fn community(&self) -> &str {
        self.ledger.community()
    }

    /// Project the actual ledger and certificate issuer for Policy/Beacon.
    /// This is a host publication port, absent from member request variants.
    #[cfg(feature = "publication")]
    pub fn public_verifier_material(
        &mut self,
        revision: u64,
        policy_epoch: u64,
    ) -> Result<crate::publication::PublicVerifierMaterial, Error> {
        self.ledger.public_verifier_material(
            revision,
            policy_epoch,
            self.extension_issuer
                .as_ref()
                .ok_or(Error::UnsupportedCapability)?,
        )
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
            AccountServiceRequest::RegisterRecordRecipient { grant, .. }
            | AccountServiceRequest::Apply { grant, .. }
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
            AccountServiceRequest::RegisterRecordRecipient {
                grant,
                authorization,
                request,
            } => {
                self.ledger.register_record_recipient(
                    &grant,
                    &authorization,
                    &request,
                    &self.clock,
                )?;
                Ok(AccountServiceResponse::RecordRecipient {
                    recipient_key: request.recipient_key,
                })
            }
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
                let result = self.ledger.apply_extended_certified(
                    &grant,
                    &authorization,
                    &request,
                    &update,
                    issuer,
                    &self.clock,
                )?;
                let acceptance = result.acceptance;
                let certificate = self.ledger.certify_extended(&acceptance, issuer)?;
                Ok(AccountServiceResponse::ApplyExtended {
                    acceptance,
                    certificate,
                    ancestry: result.ancestry.map(Box::new),
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

    /// Scheduled common publication, not a member request or activity check.
    pub fn publish_record_epoch(
        &mut self,
        policy_epoch: u64,
        period_seconds: u64,
    ) -> Result<crate::accounting_ledger::record_epoch::RecordEpochPublication, Error> {
        self.ledger.reload_policy()?;
        self.ledger
            .publish_record_epoch(policy_epoch, period_seconds, &self.clock)
    }

    /// Privileged original delayed settlement batch, absent from member DTOs.
    /// The configured native ledger owns all proof, replay, delay and commit rules.
    pub fn deposit_batch(
        &mut self,
        batch: &[(crate::extensions::Deposit, Vec<u8>)],
    ) -> Result<(), Error> {
        self.ledger.reload_policy()?;
        self.ledger.deposit_batch(batch, &self.clock)
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
