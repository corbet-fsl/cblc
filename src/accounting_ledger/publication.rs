//! Public configuration projection from the active accounting owner.
use super::*;
use crate::publication::{PublicVerifierMaterial, Purpose};

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Project actual active configuration for the existing Policy/Beacon
    /// publication workflow. Callers supply that workflow's durable version,
    /// epoch and configured certificate issuer, never member-request values.
    /// A stale ledger snapshot fails until its owner explicitly reloads policy.
    pub fn public_verifier_material(
        &mut self,
        revision: u64,
        policy_epoch: u64,
        issuer: &cssr::certificate::CertificateIssuer,
    ) -> Result<PublicVerifierMaterial, Error> {
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let binding = crate::publication::binding::configured(
            &extensions.artifact_config,
            &extensions.verifier.scope(),
        )?;
        if binding != extensions.artifact_binding || binding.certificate_key != issuer.public_key()
        {
            return Err(Error::PolicyMismatch);
        }
        let mut transaction = self.connection.transaction()?;
        check_config(&mut transaction, &self.config)?;
        check_extension_config(&mut transaction, Some(extensions))?;
        transaction.rollback()?;
        let material = PublicVerifierMaterial {
            purpose: Purpose::PublicVerifierV1,
            community: self.trust.community_id.clone(),
            revision,
            policy_epoch,
            policy: self.policy.clone(),
            policy_digest: self.policy_digest,
            extension_policy: extensions.policy.clone(),
            proof_scope: extensions.verifier.scope(),
            manifest_sha256: binding.manifest_sha256,
            account_response_key: self.operator.verifying_key().to_bytes(),
            certificate_key: binding.certificate_key,
        };
        material.validate(&self.trust.community_id)?;
        Ok(material)
    }
}
