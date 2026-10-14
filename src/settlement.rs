//! Anonymous daily outcome settlement. Host configuration comes from the
//! current authenticated Policy; anonymous submissions never select limits,
//! epochs, private keys or verification artifacts.
use crate::{Error, admission::MAX_INTEGER, extensions::Deposit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Original maintained opaque private issuer for trusted host transport.
/// Construct it from provisioned bytes in a wiping loader, then discard those
/// bytes before queueing. No private-key getter, serializer or clone is exposed.
#[cfg(feature = "host")]
pub use cmbl::settlement::issuer::Issuer as SettlementIssuer;

/// Actual daily owner settings inside the existing signed Balance publication.
/// The original common cryptographic context is independent of the effective
/// Policy epoch. This data is not a verified token, Deposit or member authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementCapability {
    /// Original outcome-only public key, purpose and common epoch window.
    pub epoch: cmbl::settlement::Epoch,
    /// Effective Policy authority; advancing it does not rewrite the context.
    pub policy_epoch: u64,
    /// Explicit configured period, in seconds.
    pub period_seconds: u64,
    /// Authenticated per-member allowance for this common epoch.
    pub quota: u16,
}
impl std::fmt::Debug for SettlementCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SettlementCapability")
            .field("epoch", &self.epoch.epoch)
            .field("policy_epoch", &self.policy_epoch)
            .field("period_seconds", &self.period_seconds)
            .field("quota", &self.quota)
            .finish_non_exhaustive()
    }
}
impl SettlementCapability {
    /// Check descriptor semantics against independently authenticated owners.
    /// This does not verify a token, signature, Deposit or member eligibility.
    pub fn validate(&self, community: &str, policy_epoch: u64) -> Result<(), Error> {
        if self.epoch.community != community
            || self.epoch.context().is_err()
            || self.policy_epoch == 0
            || self.policy_epoch > MAX_INTEGER
            || self.policy_epoch != policy_epoch
            || self.period_seconds == 0
            || self.period_seconds > MAX_INTEGER
            || !(1..=1024).contains(&self.quota)
        {
            return Err(Error::PolicyMismatch);
        }
        let start = self
            .epoch
            .epoch
            .checked_mul(self.period_seconds)
            .filter(|value| *value <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        let end = self
            .epoch
            .epoch
            .checked_add(1)
            .and_then(|value| value.checked_mul(self.period_seconds))
            .filter(|value| *value <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        if self.epoch.valid_from != milliseconds(start)?
            || self.epoch.valid_until != milliseconds(end)?
        {
            return Err(Error::PolicyMismatch);
        }
        Ok(())
    }
    /// Check the original common window at a seconds-based owner observation.
    pub fn check_time(&self, now: u64) -> Result<(), Error> {
        let now = milliseconds(now)?;
        if now < self.epoch.valid_from || now >= self.epoch.valid_until {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

/// Explicit trusted host settings and original provisioned common descriptor.
/// No defaults, private key, verifier callback or member-controlled quota exist.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementConfig {
    /// Common outcome-only RSA key/window, authenticated by the Policy owner.
    pub epoch: cmbl::settlement::Epoch,
    /// Exact current authenticated admission epoch for token issuance.
    pub policy_epoch: u64,
    /// Original G2 period. The daily product host supplies exactly 86,400 seconds.
    pub period_seconds: u64,
    /// Original authenticated allowance per admitted member and common epoch.
    pub quota: u16,
    /// Explicit resource bound for all durable, not-yet-applied verified facts.
    pub pending_capacity: u32,
    /// Explicit resource bound for member issuance budgets in one common epoch.
    pub issuance_members_capacity: u32,
    /// Actual independently configured room keys. The host supplies its complete
    /// room-key inventory, never keys from an anonymous request.
    pub room_epochs: Vec<cmbl::passes::Epoch>,
}
#[cfg(feature = "host")]
impl SettlementConfig {
    pub(crate) fn validate(&self, community: &str) -> Result<(), Error> {
        if self.epoch.community != community
            || self.epoch.context().is_err()
            || self.policy_epoch == 0
            || self.policy_epoch > MAX_INTEGER
            || self.period_seconds == 0
            || self.period_seconds > MAX_INTEGER
            || self.quota == 0
            || self.quota > 1024
            || self.pending_capacity == 0
            || self.pending_capacity > 1 << 20
            || self.issuance_members_capacity == 0
            || self.issuance_members_capacity > 1 << 20
            || self.room_epochs.len() > 64
        {
            return Err(Error::InvalidInput);
        }
        let start = self
            .epoch
            .epoch
            .checked_mul(self.period_seconds)
            .filter(|n| *n <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        let end = self
            .epoch
            .epoch
            .checked_add(1)
            .and_then(|n| n.checked_mul(self.period_seconds))
            .filter(|n| *n <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        if self.epoch.valid_from != milliseconds(start)?
            || self.epoch.valid_until != milliseconds(end)?
        {
            return Err(Error::PolicyMismatch);
        }
        for room in &self.room_epochs {
            if room.community != community
                || room.context().is_err()
                || room.public_key_der == self.epoch.public_key_der
            {
                return Err(Error::PolicyMismatch);
            }
        }
        Ok(())
    }
    pub(crate) fn expires_at(&self) -> u64 {
        self.epoch.valid_until / 1000
    }
}

/// Member-signed blinded issuance request. It reveals no Deposit or recipient.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementPassRequest {
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub operation: [u8; 16],
    pub blind: cmbl::settlement::BlindRequest,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Original account chat-key signature, in canonical base64url.
    pub signature: String,
}

impl std::fmt::Debug for SettlementPassRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The blinded payload and signature are deliberately left out of diagnostics.
        f.debug_struct("SettlementPassRequest")
            .field("community", &self.community)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

/// Native anonymous ingress inputs. The transport must have no member session
/// and use the original separate Tor circuit. Nothing here establishes that
/// network property or contains the hidden outcome kind.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementSubmission {
    pub deposit: Deposit,
    #[serde(with = "crate::contracts::hex_bytes")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub proof: Vec<u8>,
    #[serde(with = "crate::contracts::hex_bytes")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub token_proof: Vec<u8>,
    pub operation: [u8; 16],
}

/// Durable verification staging, NOT inbox application or G2 publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagedSettlement {
    pub deposit_digest: [u8; 32],
    pub eligible_epoch: u64,
}

/// Exact reconciliation of an original durable fact or already-applied effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "status",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum SettlementStatus {
    Staged(StagedSettlement),
    Applied { deposit_digest: [u8; 32] },
}

/// Preserve the original Deposit replay digest byte-for-byte.
pub fn deposit_digest(deposit: &Deposit) -> Result<[u8; 32], Error> {
    Ok(Sha256::digest(serde_json::to_vec(deposit).map_err(|_| Error::InvalidInput)?).into())
}

/// Domain-separated signature over the complete blinded request and deadline.
pub fn settlement_pass_request_bytes(request: &SettlementPassRequest) -> Result<Vec<u8>, Error> {
    if request.community == [0; 32]
        || request.owner == [0; 32]
        || request.operation == [0; 16]
        || request.blind.context == [0; 32]
        || request.blind.blinded.len() != cmbl::passes::RSA_BYTES
        || request.issued_at == 0
        || request.issued_at >= request.expires_at
        || request.expires_at > MAX_INTEGER
    {
        return Err(Error::InvalidInput);
    }
    let blinded: [u8; 32] = Sha256::digest(&request.blind.blinded).into();
    serde_json::to_vec(&serde_json::json!([
        "cblc.settlement-pass.request.v1",
        request.community,
        request.owner,
        request.operation,
        request.blind.context,
        blinded,
        request.issued_at,
        request.expires_at,
    ]))
    .map_err(|_| Error::InvalidInput)
}

pub(crate) fn milliseconds(seconds: u64) -> Result<u64, Error> {
    seconds.checked_mul(1000).ok_or(Error::InvalidInput)
}

#[cfg(feature = "host")]
pub(crate) fn crypto_error(error: cmbl::Error) -> Error {
    match error {
        cmbl::Error::Invalid => Error::InvalidInput,
        cmbl::Error::Capacity => Error::Capacity,
        cmbl::Error::Storage => Error::Storage,
        _ => Error::Admission,
    }
}
