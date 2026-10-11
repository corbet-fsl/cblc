//! Original public enrollment schema and detached operator transcript.
use super::{AccountingDelegation, VerifiedDelegation};
use crate::Error;
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER as HEX};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

/// Original publication purpose, distinct from account acceptance and records.
pub const ENROLLMENT_DOMAIN: &str = "cfrm.account.enrollment.v1";

/// Public account enrollment header, not a holder opening or membership grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentEntry {
    pub member_id: String,
    pub account_key: String,
    pub secret_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub delegation_digest: String,
}

impl EnrollmentEntry {
    /// Derive exactly the original header from an authenticated delegation.
    pub fn from_verified(value: &VerifiedDelegation) -> Self {
        Self::from_delegation(value.delegation(), value.digest())
    }
    pub(super) fn from_delegation(d: &AccountingDelegation, digest: [u8; 32]) -> Self {
        Self {
            member_id: d.admission.member_id.clone(),
            account_key: d.account_public_key.clone(),
            secret_hash: d.state_secret_commitment.clone(),
            issued_at: d.issued_at,
            expires_at: d.expires_at,
            delegation_digest: HEX.encode(&digest),
        }
    }
    /// Check canonical public syntax. Cryptographic authority is separate.
    pub fn validate(&self) -> Result<(), Error> {
        if self.member_id.len() != 43
            || self.account_key.len() != 128
            || self.secret_hash.len() != 64
            || self.delegation_digest.len() != 64
        {
            return Err(Error::Admission);
        }
        czkp::decode::<32>(&self.member_id).map_err(|_| Error::Admission)?;
        hex::<64>(&self.account_key)?;
        hex::<32>(&self.secret_hash)?;
        hex::<32>(&self.delegation_digest)?;
        if self.issued_at == 0
            || self.issued_at >= self.expires_at
            || self.expires_at > czkp::MAX_INTEGER
        {
            return Err(Error::Admission);
        }
        Ok(())
    }
}

/// Original whole delegation paired with its exact public header.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct EnrollmentDelegation {
    pub delegation: AccountingDelegation,
    pub entry: EnrollmentEntry,
}
impl EnrollmentDelegation {
    /// Retain only the complete authenticated public authority input.
    pub fn from_verified(value: &VerifiedDelegation) -> Self {
        Self {
            delegation: value.delegation().clone(),
            entry: EnrollmentEntry::from_verified(value),
        }
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        self.entry.validate()?;
        if self.delegation.version != 1
            || self.delegation.hash_scheme != super::ACCOUNT_HASH_SCHEME
            || !czkp::scope(&self.delegation.admission.community_id)
            || self.entry
                != EnrollmentEntry::from_delegation(&self.delegation, self.delegation.digest()?)
        {
            return Err(Error::Admission);
        }
        Ok(())
    }
}

/// Original complete common enrollment publication. Decoding or authenticating
/// its operator signature alone does not establish a verified common root.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentPublication {
    pub version: u32,
    pub domain: String,
    pub community_id: String,
    pub policy_digest: String,
    pub slot: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub root: [u8; 32],
    pub delegations: Vec<EnrollmentDelegation>,
    pub signature: String,
}
impl EnrollmentPublication {
    /// Canonical original transcript: sort unique member IDs before encoding
    /// the complete delegated authority objects. No CSGN envelope substitution.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.version != 1
            || self.domain != ENROLLMENT_DOMAIN
            || !czkp::scope(&self.community_id)
            || self.policy_digest.is_empty()
            || self.policy_digest.len() > 128
            || self.not_before >= self.expires_at
            || self.expires_at > czkp::MAX_INTEGER
            || self.slot > czkp::MAX_INTEGER
            || self.delegations.is_empty()
            || self.delegations.len() > 65536
        {
            return Err(Error::Admission);
        }
        if !self.signature.is_empty() {
            signature(&self.signature)?;
        }
        for value in &self.delegations {
            value.validate()?;
        }
        let mut delegations = self.delegations.iter().collect::<Vec<_>>();
        delegations.sort_by(|a, b| a.entry.member_id.cmp(&b.entry.member_id));
        if delegations
            .windows(2)
            .any(|pair| pair[0].entry.member_id == pair[1].entry.member_id)
        {
            return Err(Error::Admission);
        }
        // Serialize the typed ordered objects directly. Converting nested
        // structs to JSON maps would reorder their keys relative to the
        // original device authority and publication object transcripts.
        let mut bytes = PublicationBytes(Vec::new());
        serde_json::to_writer(
            &mut bytes,
            &(
                ENROLLMENT_DOMAIN,
                self.version,
                &self.community_id,
                &self.policy_digest,
                self.slot,
                self.not_before,
                self.expires_at,
                self.root,
                delegations,
            ),
        )
        .map_err(|_| Error::Admission)?;
        Ok(bytes.0)
    }
    /// Verify the original detached Ed25519 signature under an independently
    /// configured operator key. The consumer must still verify all delegations,
    /// exact scope/period/time and the maintained common tree.
    pub fn verify_signature(&self, operator: &[u8; 32]) -> Result<(), Error> {
        VerifyingKey::from_bytes(operator)
            .map_err(|_| Error::Admission)?
            .verify_strict(&self.signing_bytes()?, &signature(&self.signature)?)
            .map_err(|_| Error::Admission)
    }
}

// Original syntax ceiling. The service enforces its independently configured
// total retained byte budget separately, before persisting a pending slot.
struct PublicationBytes(Vec<u8>);
impl Write for PublicationBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > (64 * 1024 * 1024_usize).saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn hex<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    if value.len() != N * 2 {
        return Err(Error::Admission);
    }
    HEX.decode(value.as_bytes())
        .map_err(|_| Error::Admission)?
        .try_into()
        .map_err(|_| Error::Admission)
}
fn signature(value: &str) -> Result<Signature, Error> {
    if value.len() != 86 {
        return Err(Error::Admission);
    }
    let bytes = B64.decode(value.as_bytes()).map_err(|_| Error::Admission)?;
    if bytes.len() != 64 || B64.encode(&bytes) != value {
        return Err(Error::Admission);
    }
    Signature::from_slice(&bytes).map_err(|_| Error::Admission)
}
