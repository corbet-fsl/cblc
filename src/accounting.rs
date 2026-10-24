//! Wire and verification boundary for the experimental private account relation.
//!
//! These types do not enable `AllocationLedger::resolve_private`. A host must
//! supply the pinned, complete proof verifier; signatures alone do not establish
//! a valid hidden account transition.

use crate::{
    Error,
    admission::{MAX_INTEGER, decode, signature},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) use czkp::field;

pub use crate::accounting_policy::AccountPolicy;

/// Complete public input. The role, peer, nonce, group, balances and map paths
/// belong exclusively to the private witness and cannot be added to this wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountStatement {
    pub protocol_version: u32,
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub policy_digest: [u8; 32],
    pub enrollment_root: [u8; 32],
    pub now: u64,
    pub valid_until: u64,
    pub genesis: bool,
    pub previous_version: u64,
    pub next_version: u64,
    pub previous_state: [u8; 32],
    pub next_state: [u8; 32],
    pub settlement_marker: [u8; 32],
    pub policy: AccountPolicy,
}

pub fn statement_bytes(value: &AccountStatement) -> Result<Vec<u8>, Error> {
    value.policy.validate()?;
    field(&value.enrollment_root, true)?;
    field(&value.previous_state, !value.genesis)?;
    field(&value.next_state, true)?;
    field(&value.settlement_marker, false)?;
    if value.protocol_version != 2
        || value.now < value.policy.policy_valid_from
        || value.now >= value.policy.policy_valid_until
        || value.valid_until != value.policy.proof_valid_until(value.now)?
        || value.next_version > MAX_INTEGER
        || (value.genesis
            && (value.previous_version != 0
                || value.next_version != 0
                || value.previous_state != [0; 32]
                || value.settlement_marker != [0; 32]))
        || (!value.genesis && value.previous_version.checked_add(1) != Some(value.next_version))
        || value.policy.digest(&value.community)? != value.policy_digest
    {
        return Err(Error::InvalidInput);
    }
    Ok(value.fields().bytes())
}

impl AccountStatement {
    /// The statement fields as czkp's canonical transcript encoder consumes them.
    pub fn fields(&self) -> czkp::account::StatementFields {
        czkp::account::StatementFields {
            protocol_version: self.protocol_version,
            community: self.community,
            owner: self.owner,
            policy_digest: self.policy_digest,
            enrollment_root: self.enrollment_root,
            now: self.now,
            valid_until: self.valid_until,
            genesis: self.genesis,
            previous_version: self.previous_version,
            next_version: self.next_version,
            previous_state: self.previous_state,
            next_state: self.next_state,
            settlement_marker: self.settlement_marker,
            policy: self.policy.fields(),
        }
    }
}

pub use czkp::ProofScope as AccountProofScope;

/// Security-critical host dependency, configured independently of a request.
/// `verify` must verify the actual proof against *all* supplied public inputs
/// with the circuit and VK named by `scope`. There is no permissive default.
/// Hosts use the shipped native adapter; test wrappers preserve real verification.
pub trait AccountProofVerifier {
    fn scope(&self) -> AccountProofScope;
    fn verify(&self, statement: &AccountStatement, proof: &[u8]) -> Result<(), Error>;
}

/// Longest lifetime of a GENESIS account request: from its proof statement time
/// (`issued_at == statement.now`) to its `expires_at`. A technical window that either
/// fits or not, so a code constant read by the device and by acceptance alike; the
/// rulebook's `maxAuthorizationSeconds` no longer decides genesis acceptance (it still
/// bounds account updates, obligations, status requests and record presentations).
/// The window must cover the slowest supported device's genesis proof plus checkpoint
/// refreshes, signing and the network: p99 of the slowest supported prover (a
/// single-thread browser prover on a laptop core twice as slow as the reference host,
/// 109 s for the 2^19 circuit) times 1.5, plus 25 s for four requests over Tor
/// = 189 s, rounded up. The deadline runs from the request's own proof time, not from
/// the end of the rate window that contains it. The checkpoint slot still caps it.
pub const GENESIS_PROOF_WINDOW_SECONDS: u64 = 190;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountRequest {
    pub statement: AccountStatement,
    pub request_id: [u8; 32],
    pub proof_scope: AccountProofScope,
    pub chat_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub proof: Vec<u8>,
    pub signature: String,
}

pub fn account_request_bytes(value: &AccountRequest) -> Result<Vec<u8>, Error> {
    if value.request_id == [0; 32]
        || value.issued_at != value.statement.now
        || value.issued_at >= value.expires_at
        || value.expires_at > MAX_INTEGER
        || value.expires_at > value.statement.valid_until
        || value.proof.is_empty()
    {
        return Err(Error::InvalidInput);
    }
    let mut bytes = b"cfrm.account.request.v1\0".to_vec();
    bytes.extend_from_slice(&value.request_id);
    bytes.extend_from_slice(&value.proof_scope.circuit_digest);
    bytes.extend_from_slice(&value.proof_scope.verifying_key_digest);
    bytes.extend_from_slice(&decode::<32>(&value.chat_public_key)?);
    bytes.extend_from_slice(&value.issued_at.to_be_bytes());
    bytes.extend_from_slice(&value.expires_at.to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(statement_bytes(&value.statement)?));
    bytes.extend_from_slice(&Sha256::digest(&value.proof));
    Ok(bytes)
}

pub fn account_request_digest(value: &AccountRequest) -> Result<[u8; 32], Error> {
    let mut bytes = account_request_bytes(value)?;
    bytes.extend_from_slice(&decode::<64>(&value.signature)?);
    Ok(Sha256::digest(bytes).into())
}

/// The operator certifies acceptance of an opaque state. Peers additionally
/// need the private reservation proof and current cmsg consent before release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountAcceptance {
    pub statement: AccountStatement,
    pub request_id: [u8; 32],
    pub request_digest: [u8; 32],
    pub proof_scope: AccountProofScope,
    pub accepted_at: u64,
    pub signature: String,
}

pub fn account_acceptance_bytes(value: &AccountAcceptance) -> Result<Vec<u8>, Error> {
    if value.request_id == [0; 32]
        || value.accepted_at < value.statement.now
        || value.accepted_at >= value.statement.valid_until
    {
        return Err(Error::InvalidInput);
    }
    statement_bytes(&value.statement)?;
    Ok(czkp::account::acceptance_bytes(
        &value.request_id,
        &value.request_digest,
        &value.proof_scope,
        value.accepted_at,
        &value.statement.fields(),
    ))
}

pub fn verify_account_acceptance(
    value: &AccountAcceptance,
    operator_key: &[u8; 32],
) -> Result<(), Error> {
    czkp::account::verify_acceptance(
        &account_acceptance_bytes(value)?,
        operator_key,
        &decode::<64>(&value.signature)?,
    )
}

/// A fresh, authenticated request can recover an old accepted response after
/// its original device/request expires. A new device needs root authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountStatusRequest {
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub request_id: Option<[u8; 32]>,
    pub challenge: [u8; 32],
    pub chat_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

pub fn account_status_bytes(value: &AccountStatusRequest) -> Result<Vec<u8>, Error> {
    if value.challenge == [0; 32]
        || value.issued_at == 0
        || value.issued_at >= value.expires_at
        || value.expires_at > MAX_INTEGER
        || value.request_id == Some([0; 32])
    {
        return Err(Error::InvalidInput);
    }
    let mut bytes = b"cfrm.account.status.v1\0".to_vec();
    bytes.extend_from_slice(&value.community);
    bytes.extend_from_slice(&value.owner);
    bytes.push(u8::from(value.request_id.is_some()));
    bytes.extend_from_slice(&value.request_id.unwrap_or([0; 32]));
    bytes.extend_from_slice(&value.challenge);
    bytes.extend_from_slice(&decode::<32>(&value.chat_public_key)?);
    bytes.extend_from_slice(&value.issued_at.to_be_bytes());
    bytes.extend_from_slice(&value.expires_at.to_be_bytes());
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountStatusResponse {
    /// Binds the fresh challenge, owner, requested lookup and caller authority.
    pub status_request_digest: [u8; 32],
    pub observed_at: u64,
    pub acceptance: Option<AccountAcceptance>,
    /// Issuer evidence of the same accepted extended request, so a returning holder
    /// can rebuild the full response. Not covered by `signature`: both parts carry
    /// their own issuer signature that the holder verifies against the acceptance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schema(value_type = Option<Object>))]
    pub extended: Option<crate::extensions::ExtendedEvidence>,
    pub signature: String,
}

pub fn account_status_response_bytes(value: &AccountStatusResponse) -> Result<Vec<u8>, Error> {
    if value.observed_at == 0 || value.observed_at > MAX_INTEGER {
        return Err(Error::InvalidInput);
    }
    let mut bytes = b"cfrm.account.status-response.v1\0".to_vec();
    bytes.extend_from_slice(&value.status_request_digest);
    bytes.extend_from_slice(&value.observed_at.to_be_bytes());
    bytes.push(u8::from(value.acceptance.is_some()));
    let accepted = match &value.acceptance {
        Some(acceptance) => {
            if acceptance.accepted_at > value.observed_at {
                return Err(Error::InvalidInput);
            }
            let mut signed = account_acceptance_bytes(acceptance)?;
            signed.extend_from_slice(&decode::<64>(&acceptance.signature)?);
            Sha256::digest(signed).into()
        }
        None => [0; 32],
    };
    bytes.extend_from_slice(&accepted);
    Ok(bytes)
}

/// Verify the reply to the *exact* fresh status challenge. An old signed
/// acceptance alone is insufficient evidence that it is the current state.
pub fn verify_account_status_response(
    value: &AccountStatusResponse,
    request: &AccountStatusRequest,
    operator_key: &[u8; 32],
) -> Result<(), Error> {
    let mut signed_request = account_status_bytes(request)?;
    signed_request.extend_from_slice(&decode::<64>(&request.signature)?);
    let request_digest: [u8; 32] = Sha256::digest(signed_request).into();
    if value.status_request_digest != request_digest
        || value.observed_at < request.issued_at
        || value.observed_at >= request.expires_at
    {
        return Err(Error::Replay);
    }
    if let Some(acceptance) = &value.acceptance {
        if acceptance.statement.owner != request.owner
            || acceptance.statement.community != request.community
            || request
                .request_id
                .is_some_and(|id| id != acceptance.request_id)
        {
            return Err(Error::Admission);
        }
        verify_account_acceptance(acceptance, operator_key)?;
    }
    signature(
        &data_encoding::BASE64URL_NOPAD.encode(operator_key),
        &account_status_response_bytes(value)?,
        &value.signature,
    )
}
