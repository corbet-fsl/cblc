//! One fixed activation commitment, not member state or a proof verdict.
#[cfg(test)]
use super::tuning::check_epoch_config;
use super::tuning::{StoredConfig, check_epoch_config_in};
use crate::storage::Transaction;
use crate::{
    Error, accounting::statement_bytes, artifacts::ArtifactBinding, extensions::ExtensionActivation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ActivationAnchor {
    format: String,
    original_config: Vec<u8>,
    statement_sha256: [u8; 32],
    proof_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
}

impl ActivationAnchor {
    pub(super) fn new(
        config: &[u8],
        activation: &ExtensionActivation,
        binding: &ArtifactBinding,
    ) -> Result<Self, Error> {
        Ok(Self {
            format: "cblc.extension-activation.v2".into(),
            original_config: config.to_vec(),
            statement_sha256: Sha256::digest(statement_bytes(&activation.account)?).into(),
            proof_sha256: Sha256::digest(&activation.proof).into(),
            manifest_sha256: binding.manifest_sha256,
        })
    }

    #[cfg(test)]
    pub(super) fn check(
        &self,
        current_config: &[u8],
        activation: &ExtensionActivation,
        binding: &ArtifactBinding,
    ) -> Result<(), Error> {
        check_epoch_config(&self.original_config, current_config)?;
        self.check_binding(activation, binding)
    }

    pub(super) fn check_in(
        &self,
        transaction: &mut Transaction<'_>,
        current_config: &[u8],
        activation: &ExtensionActivation,
        binding: &ArtifactBinding,
    ) -> Result<(), Error> {
        // Only the original waiting change or a durably authenticated CSGN
        // successor can relate this historical config to the current owner.
        check_epoch_config_in(transaction, &self.original_config, current_config)?;
        self.check_binding(activation, binding)
    }

    fn check_binding(
        &self,
        activation: &ExtensionActivation,
        binding: &ArtifactBinding,
    ) -> Result<(), Error> {
        let original: StoredConfig =
            serde_json::from_slice(&self.original_config).map_err(|_| Error::Storage)?;
        if activation.account.policy != original.policy.account
            || *self != Self::new(&self.original_config, activation, binding)?
        {
            return Err(Error::PolicyMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/internal/extension_activation.rs"]
mod tests;
