//! One fixed activation commitment, not member state or a proof verdict.
use super::tuning::{StoredConfig, check_epoch_config};
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
    certificate_key: Vec<u8>,
}

impl ActivationAnchor {
    pub(super) fn new(
        config: &[u8],
        activation: &ExtensionActivation,
        binding: &ArtifactBinding,
    ) -> Result<Self, Error> {
        Ok(Self {
            format: "cblc.extension-activation.v1".into(),
            original_config: config.to_vec(),
            statement_sha256: Sha256::digest(statement_bytes(&activation.account)?).into(),
            proof_sha256: Sha256::digest(&activation.proof).into(),
            manifest_sha256: binding.manifest_sha256,
            certificate_key: binding.certificate_key.to_vec(),
        })
    }

    pub(super) fn check(
        &self,
        current_config: &[u8],
        activation: &ExtensionActivation,
        binding: &ArtifactBinding,
    ) -> Result<(), Error> {
        // This comparison permits only the original durable waiting-period
        // successor. It does not admit an arbitrary new trust ring or policy.
        check_epoch_config(&self.original_config, current_config)?;
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
