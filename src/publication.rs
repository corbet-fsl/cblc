//! Authenticated public policy and proof-artifact bindings. This is not a
//! member-currentness, reservation, release or punishment capability.
use crate::{
    Error, accounting::AccountProofScope, extensions::ExtensionPolicy,
    ledger_policy::AccountLedgerPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Strict payload purpose inside the existing SettingsSnapshot envelope kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Purpose {
    #[serde(rename = "cblc.public-verifier.v2")]
    PublicVerifierV2,
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
    /// Current economic proof policy, including durably tuned waiting time.
    pub policy_digest: [u8; 32],
    /// Immutable eligibility policy from the configured admission trust. This
    /// is independent of economic tuning and has no legacy/default projection.
    pub admission_policy_digest: [u8; 32],
    pub extension_policy: ExtensionPolicy,
    pub proof_scope: AccountProofScope,
    pub manifest_sha256: [u8; 32],
    pub account_response_key: [u8; 32],
    /// Uncompressed affine coordinates, matching the existing manifest encoding.
    pub certificate_key: Vec<u8>,
    /// Original common outcome context and effective current issuance authority.
    /// Missing legacy data confers no G5 capability; configured hosts require it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement: Option<crate::settlement::SettlementCapability>,
    /// Still-valid frozen minimum frontier, re-endorsed by this current material.
    /// Its original Policy epoch and packet/proof bytes never change on refresh.
    /// Absence does not authorize a mandatory record decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_epoch: Option<czkp::record::Epoch>,
    /// The portable Wave verifier policy, derived from the fields above by
    /// [`PublicVerifierMaterial::wave_policy`]. It travels in the document only because
    /// the device-side verifier (cwlt) cannot link this crate; `validate` recomputes it, so
    /// a descriptor that differs from the derivation in any field is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wave_verifier: Option<WaveVerifierDescriptor>,
}

/// Exactly the JSON shape of `cwlt::wave::WavePolicy`: the independently authenticated
/// parameters a device needs to verify a counterpart's Wave and outcome proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WaveVerifierDescriptor {
    /// SHA-256 of the community identifier, as in every account statement.
    pub community: [u8; 32],
    pub extension: ExtensionPolicy,
    pub proof_scope: AccountProofScope,
    pub certificate_key: Vec<u8>,
    pub manifest_sha256: [u8; 32],
    /// The account state policy digest (`AccountPolicy::state_digest`).
    pub state_policy: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
}

impl PublicVerifierMaterial {
    /// Derive the Wave verifier policy from the published material alone: community,
    /// extension policy, account proof scope, issuer key and manifest pin as published,
    /// the state policy from the account policy, and the account policy's validity window.
    pub fn wave_policy(&self) -> Result<WaveVerifierDescriptor, Error> {
        let community: [u8; 32] = Sha256::digest(self.community.as_bytes()).into();
        Ok(WaveVerifierDescriptor {
            community,
            extension: self.extension_policy.clone(),
            proof_scope: self.proof_scope.clone(),
            certificate_key: self.certificate_key.clone(),
            manifest_sha256: self.manifest_sha256,
            state_policy: self.policy.account.state_digest(&community)?,
            valid_from: self.policy.account.policy_valid_from,
            valid_until: self.policy.account.policy_valid_until,
        })
    }
    /// Check public policy validity after authenticating the document through
    /// the independently configured publication ring. No member fact is returned.
    pub fn validate_at(&self, issuer: &str, now: u64) -> Result<(), Error> {
        self.validate(issuer)?;
        if let Some(settlement) = &self.settlement {
            settlement.check_time(now)?;
        }
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
        self.extension_policy.validate()?;
        if let Some(descriptor) = &self.wave_verifier
            && *descriptor != self.wave_policy()?
        {
            return Err(Error::PolicyMismatch);
        }
        if let Some(settlement) = &self.settlement {
            settlement.validate(&self.community, self.policy_epoch)?;
        }
        if let Some(record) = &self.record_epoch {
            // The descriptor cannot choose the relying owner's authenticated period.
            let period = record
                .expires_at
                .checked_sub(record.starts_at)
                .ok_or(Error::InvalidInput)?;
            record.validate(&community, period)?;
            if record.policy_epoch == 0
                || record.policy_epoch > self.policy_epoch
                || record.proof_scope != self.proof_scope
            {
                return Err(Error::PolicyMismatch);
            }
        }
        Ok(())
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
