//! Canonical cpns change permission: exact field, old revision and replacement.
use crate::{
    Error,
    accounting::{AccountAcceptance, AccountProofScope, AccountRequest},
    extensions::{Effect, ExtendedUpdate, ExtensionPolicy, verify_extended_acceptance},
};
use cpns::server::{Change, ChangeTokenVerifier, TokenRejected};
use sha2::{Digest, Sha256};

/// Canonical SHA-256 binding. `member` is cpsd's lowercase 96-character hex
/// pseudonym, as stored by the membership register; it is never a root key.
pub fn change_binding(change: &Change<'_>) -> Result<[u8; 32], Error> {
    change.next_pin().map_err(|_| Error::InvalidInput)?;
    let _ = owner(change.member)?;
    let mut hash = Sha256::new();
    hash.update(b"cblc.cpns-change.v1\0");
    for value in [
        change.community.as_bytes(),
        change.member.as_bytes(),
        change.field.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update(change.expected.revision.to_be_bytes());
    hash.update(change.expected.fingerprint.as_bytes());
    hash.update(change.replacement.as_bytes());
    Ok(hash.finalize().into())
}
fn owner(member: &str) -> Result<[u8; 32], Error> {
    let bytes = data_encoding::HEXLOWER
        .decode(member.as_bytes())
        .map_err(|_| Error::InvalidInput)?;
    if bytes.len() != 48 {
        return Err(Error::InvalidInput);
    }
    Ok(Sha256::digest(bytes).into())
}
/// Evidence of a completed spend, never an unspent balance proof.
pub struct SpentChange {
    pub acceptance: AccountAcceptance,
    pub request: AccountRequest,
    pub update: ExtendedUpdate,
}
/// Pin this adapter to the issuer, complete extension relation and policy.
pub struct PinSpendVerifier {
    pub operator_key: [u8; 32],
    pub scope: AccountProofScope,
    pub policy: ExtensionPolicy,
}
impl ChangeTokenVerifier for PinSpendVerifier {
    type Token = SpentChange;
    async fn verify_spent(
        &self,
        change: &Change<'_>,
        token: &SpentChange,
    ) -> Result<(), TokenRejected> {
        let binding = change_binding(change).map_err(|_| TokenRejected)?;
        let community: [u8; 32] = Sha256::digest(change.community.as_bytes()).into();
        if token.request.statement.community != community
            || token.request.statement.owner != owner(change.member).map_err(|_| TokenRejected)?
            || token.request.proof_scope != self.scope
            || token.update.effect != (Effect::Change { binding })
        {
            return Err(TokenRejected);
        }
        verify_extended_acceptance(
            &token.acceptance,
            &token.request,
            &token.update,
            &self.policy,
            &self.operator_key,
        )
        .map_err(|_| TokenRejected)
    }
}
