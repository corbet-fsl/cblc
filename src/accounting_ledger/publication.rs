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
        let binding = &extensions.artifact_binding;
        if binding.certificate_key.as_slice() != issuer.public_key() {
            return Err(Error::PolicyMismatch);
        }
        let mut transaction = self.connection.transaction()?;
        check_config(&mut transaction, &self.config)?;
        check_extension_config(&mut transaction, Some(extensions))?;
        let record_epoch = super::record_epoch::public_descriptor(
            &mut transaction,
            &self.community,
            policy_epoch,
            &extensions.verifier.scope(),
            &self.config,
            &extensions.config,
        )?;
        let settlement = super::settlement::public_settings(
            &mut transaction,
            self.settlement.as_ref(),
            policy_epoch,
        )?;
        transaction.rollback()?;
        let material = PublicVerifierMaterial {
            purpose: Purpose::PublicVerifierV2,
            community: self.trust.community_id.clone(),
            revision,
            policy_epoch,
            policy: self.policy.clone(),
            policy_digest: self.policy_digest,
            admission_policy_digest: decode::<32>(&self.trust.policy_digest)?,
            extension_policy: extensions.policy.clone(),
            proof_scope: extensions.verifier.scope(),
            manifest_sha256: binding.manifest_sha256,
            account_response_key: self.operator.verifying_key().to_bytes(),
            certificate_key: binding.certificate_key.to_vec(),
            settlement,
            record_epoch,
            wave_verifier: None,
        };
        let material = PublicVerifierMaterial {
            wave_verifier: Some(material.wave_policy()?),
            ..material
        };
        material.validate(&self.trust.community_id)?;
        Ok(material)
    }
}
