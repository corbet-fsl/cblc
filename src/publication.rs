//! Authenticated public policy and proof-artifact bindings. This is not a
//! member-currentness, reservation, release or punishment capability.
use crate::{
    Error, accounting::AccountProofScope, accounting_ledger::AccountLedgerPolicy,
    extensions::ExtensionPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub(crate) mod binding;

/// Strict payload purpose inside the existing SettingsSnapshot envelope kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Purpose {
    #[serde(rename = "cblc.public-verifier.v1")]
    PublicVerifierV1,
}

/// One canonical owner document. Signature and durable publication floors are
/// supplied by Policy/Beacon; merely deserializing this type authenticates nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicVerifierMaterial {
    pub purpose: Purpose,
    pub community: String,
    pub revision: u64,
    pub policy_epoch: u64,
    pub policy: AccountLedgerPolicy,
    pub policy_digest: [u8; 32],
    pub extension_policy: ExtensionPolicy,
    pub proof_scope: AccountProofScope,
    pub manifest_sha256: [u8; 32],
    pub account_response_key: [u8; 32],
    /// Uncompressed affine coordinates, matching the existing manifest encoding.
    pub certificate_key: Vec<u8>,
}

impl PublicVerifierMaterial {
    /// Check public policy validity after authenticating the document through
    /// the independently configured publication ring. No member fact is returned.
    pub fn validate_at(&self, issuer: &str, now: u64) -> Result<(), Error> {
        self.validate(issuer)?;
        self.policy.account.proof_valid_until(now)?;
        Ok(())
    }
    /// Validate only public document semantics, never a member or record claim.
    pub fn validate(&self, issuer: &str) -> Result<(), Error> {
        if self.community != issuer || !crate::admission::scope(&self.community) {
            return Err(Error::Admission);
        }
        if self.revision == 0
            || self.revision > czkp::MAX_INTEGER
            || self.policy_epoch == 0
            || self.policy_epoch > czkp::MAX_INTEGER
            || self.policy.max_proof_bytes < crate::extensions::EXTENSION_PROOF_BYTES
            || self.proof_scope.circuit_digest == [0; 32]
            || self.proof_scope.verifying_key_digest == [0; 32]
            || self.manifest_sha256 == [0; 32]
            || self.account_response_key == [0; 32]
            || self.certificate_key.len() != 64
        {
            return Err(Error::InvalidInput);
        }
        self.policy.validate()?;
        let community = Sha256::digest(self.community.as_bytes()).into();
        if self.policy.account.digest(&community)? != self.policy_digest {
            return Err(Error::PolicyMismatch);
        }
        self.extension_policy.validate()
    }
}

impl cbcn::document::Document for PublicVerifierMaterial {
    const KIND: csgn::Kind = csgn::Kind::SettingsSnapshot;

    fn version(&self, issuer: &str) -> cbcn::Result<cbcn::document::Version> {
        self.validate(issuer).map_err(|_| cbcn::Error::Incoherent)?;
        Ok(cbcn::document::Version {
            revision: self.revision,
            epoch: self.policy_epoch,
        })
    }
}
