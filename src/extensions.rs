//! Proof-gated extensions. V2 circuits cannot authorize any of these statements.
use crate::{
    Error,
    accounting::{AccountProofScope, AccountStatement},
    storage::{Transaction, key},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Mandatory platform policy; no implicit quorum or economic defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionPolicy {
    pub revision: u64,
    pub public_record_quorum: u32,
    pub change_token_cost: u32,
    pub deposit_delay_seconds: u64,
    pub minimum_deposit_batch: u8,
}
impl ExtensionPolicy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.revision == 0
            || self.revision > czkp::MAX_INTEGER
            || self.public_record_quorum == 0
            || self.change_token_cost == 0
            || self.deposit_delay_seconds == 0
            || self.deposit_delay_seconds > czkp::MAX_INTEGER
            || !(2..=64).contains(&self.minimum_deposit_batch)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Settlement frontier, not a balance or an outcome counter.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Inbox {
    pub root: [u8; 32],
}
/// Pending opaque entry, removed atomically when its recipient consumes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingObligation {
    pub previous: Inbox,
    pub commitment: [u8; 32],
}
/// Private input to a delayed deposit proof, returned only to the accepting holder.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateCertificate {
    pub accepted_at: u64,
    pub signature: Vec<u8>,
}
/// The public effect to prove in addition to all ordinary account constraints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Effect {
    /// Apply every queued obligation before any other state change.
    Update,
    /// Spend the configured units and bind permission to this opaque field commitment.
    Change { binding: [u8; 32] },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtendedUpdate {
    pub previous_inbox: Inbox,
    pub inbox: Inbox,
    pub effect: Effect,
}
/// A recipient-addressed opaque obligation, delivered without the punished holder.
/// The proof hides the reporter, receipt, conversation and kind of outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Deposit {
    /// Coarse release horizon. The circuit proves acceptance preceded it by the configured delay.
    pub release_epoch: u64,
    pub community: [u8; 32],
    pub recipient: [u8; 32],
    pub nullifier: [u8; 32],
    pub authorization_nullifier: [u8; 32],
    pub obligation: [u8; 32],
}
/// Every visibility/contact decision carries an action-specific, fresh record proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum RecordUse {
    FirstContact,
    ForumListing,
}
/// A challenge supplied by the relying service for exactly one decision context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordContext {
    pub purpose: RecordUse,
    pub challenge: [u8; 32],
    pub expires_at: u64,
}
/// Relative public values only: 10,000 basis points in accepted/declined/punished order.
/// The proof establishes the hidden total reaches the configured quorum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicRecord {
    pub context: RecordContext,
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub version: u64,
    pub state: [u8; 32],
    pub inbox: Inbox,
    pub shares: Option<[u16; 3]>,
}
/// Complete, domain-separated verifier input. The backend must bind every field.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ExtensionStatement {
    Update {
        policy: ExtensionPolicy,
        account: Box<AccountStatement>,
        update: ExtendedUpdate,
    },
    Deposit {
        policy: ExtensionPolicy,
        deposit: Deposit,
    },
    Record {
        policy: ExtensionPolicy,
        record: PublicRecord,
    },
}
pub(crate) mod sealed {
    pub trait Sealed {}
}
/// Required transport budget for 64 ingestion proofs plus one final action.
/// The pinned proof encoding and its JSON framing fit within this bounded size.
pub const EXTENSION_PROOF_BYTES: usize = 4 * 1024 * 1024;
/// Backend for the complete extension relation. Only the shipped process adapter
/// implements this sealed trait; a caller cannot substitute a signed verdict.
pub trait ExtensionVerifier: sealed::Sealed + Send {
    fn scope(&self) -> AccountProofScope;
    fn verify(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error>;
    /// Use a separate bounded pool for unauthenticated work.
    fn verify_anonymous(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error>;
}
/// A real genesis proof used to check the configured relation before activation.
/// This probe does not admit or create an account. Normal authenticated issuance
/// must still verify and atomically accept that member's request afterward.
pub struct ExtensionActivation {
    pub account: AccountStatement,
    pub proof: Vec<u8>,
}
pub(crate) struct Extensions {
    pub policy: ExtensionPolicy,
    pub verifier: Box<dyn ExtensionVerifier>,
    pub config: Vec<u8>,
    pub budget: crate::verification::Budget,
}
pub(crate) fn inbox(tx: &mut Transaction<'_>, owner: &[u8; 32]) -> Result<Inbox, Error> {
    Ok(tx.get(&key(5, &[owner]))?.unwrap_or_default())
}
pub(crate) fn applied(tx: &mut Transaction<'_>, owner: &[u8; 32]) -> Result<Inbox, Error> {
    Ok(tx.get(&key(7, &[owner]))?.unwrap_or_default())
}
pub(crate) fn advance(previous: &Inbox, deposit: &Deposit) -> Result<Inbox, Error> {
    let mut hash = Sha256::new();
    hash.update(b"cblc.obligation-inbox.v2\0");
    hash.update(deposit.community);
    hash.update(deposit.recipient);
    hash.update(previous.root);
    hash.update(deposit.obligation);
    Ok(Inbox {
        root: hash.finalize().into(),
    })
}

/// Canonical acceptance binding for extended requests, including the effect and
/// pinned extension policy/scope. This is also the exact-retry identity.
pub fn extended_request_digest(
    request: &crate::accounting::AccountRequest,
    update: &ExtendedUpdate,
    policy: &ExtensionPolicy,
) -> Result<[u8; 32], Error> {
    policy.validate()?;
    let config =
        serde_json::to_vec(&(policy, &request.proof_scope)).map_err(|_| Error::InvalidInput)?;
    let binding = serde_json::to_vec(&(
        b"cblc.extended-request.v1",
        crate::accounting::account_request_digest(request)?,
        config,
        update,
    ))
    .map_err(|_| Error::InvalidInput)?;
    Ok(Sha256::digest(binding).into())
}
/// Verify a returned acceptance for the exact effect before consuming permission
/// in another server component. That component must still make its own use atomic.
pub fn verify_extended_acceptance(
    acceptance: &crate::accounting::AccountAcceptance,
    request: &crate::accounting::AccountRequest,
    update: &ExtendedUpdate,
    policy: &ExtensionPolicy,
    operator_key: &[u8; 32],
) -> Result<(), Error> {
    if acceptance.statement != request.statement
        || acceptance.request_id != request.request_id
        || acceptance.proof_scope != request.proof_scope
        || acceptance.request_digest != extended_request_digest(request, update, policy)?
    {
        return Err(Error::Replay);
    }
    crate::accounting::verify_account_acceptance(acceptance, operator_key)
}
