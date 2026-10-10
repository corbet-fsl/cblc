//! Separate anonymous verification capacity and ephemeral cthl admission limits.
use crate::{
    Error,
    accounting::AccountProofScope,
    extensions::{ExtensionStatement, ExtensionVerifier},
};
use std::{num::NonZeroUsize, time::Duration};

/// Explicit host resource policy, independent of economic proof policy.
#[derive(Clone, Copy)]
pub struct ExtensionLimits {
    pub global_burst: u32,
    pub subject_burst: u32,
    pub replenish: Duration,
    pub maximum_keys: NonZeroUsize,
}

pub(crate) struct Budget(cthl::Throttle<cthl::MemoryStore>);
impl Budget {
    pub fn new(community: &str, limits: ExtensionLimits) -> Result<Self, Error> {
        let global = cthl::Limit::new(limits.global_burst, limits.replenish)
            .map_err(|_| Error::InvalidInput)?;
        let subject = cthl::Limit::new(limits.subject_burst, limits.replenish)
            .map_err(|_| Error::InvalidInput)?;
        Ok(Self(
            cthl::Throttle::new(
                community,
                [("global", global), ("subject", subject)],
                cthl::MemoryStore::new(limits.maximum_keys),
            )
            .map_err(|_| Error::InvalidInput)?,
        ))
    }
    pub fn check(&self, subject: &[u8; 32]) -> Result<(), Error> {
        for (key, action) in [
            (b"anonymous".as_slice(), "global"),
            (subject.as_slice(), "subject"),
        ] {
            match futures::executor::block_on(self.0.check(key, action))
                .map_err(|_| Error::Capacity)?
            {
                cthl::Decision::Allowed => {}
                cthl::Decision::Denied { .. } => return Err(Error::Capacity),
            }
        }
        Ok(())
    }
}

/// Native verification with independent authenticated and anonymous capacity.
/// Deposit and record circuits share the same anonymous admission pool.
pub struct NativeExtensionVerifier {
    scope: AccountProofScope,
    issuer: [u8; 64],
    #[cfg(feature = "publication")]
    pub(crate) artifact_binding: crate::artifacts::ArtifactBinding,
    updates: cvfy::NativeVerifier,
    deposits: cvfy::NativeVerifier,
    records: cvfy::NativeVerifier,
    update_timeout: Duration,
    anonymous_timeout: Duration,
}
impl crate::extensions::sealed::Sealed for NativeExtensionVerifier {}
impl NativeExtensionVerifier {
    pub fn new(
        updates: crate::artifacts::NativeVerifierOptions,
        anonymous: crate::artifacts::NativeVerifierOptions,
        artifacts: crate::artifacts::ExtensionArtifacts,
    ) -> Result<Self, Error> {
        let capacity = cvfy::NativeCapacity::new(anonymous.maximum_parallel)?;
        let update_timeout = updates.timeout;
        let anonymous_timeout = anonymous.timeout;
        let [updates, deposits, records] = artifacts.configs(updates, anonymous);
        Ok(Self {
            scope: artifacts.scope(),
            issuer: artifacts.issuer,
            #[cfg(feature = "publication")]
            artifact_binding: artifacts.binding(),
            updates: cvfy::NativeVerifier::new(updates)?,
            deposits: cvfy::NativeVerifier::with_capacity(deposits, capacity.clone())?,
            records: cvfy::NativeVerifier::with_capacity(records, capacity)?,
            update_timeout,
            anonymous_timeout,
        })
    }
}
impl ExtensionVerifier for NativeExtensionVerifier {
    fn scope(&self) -> AccountProofScope {
        self.scope.clone()
    }
    fn verify(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        if !matches!(statement, ExtensionStatement::Update { .. }) {
            return Err(Error::InvalidInput);
        }
        let deadline = std::time::Instant::now() + self.update_timeout;
        let prepared = crate::prepared::extension_proofs(
            statement,
            proof,
            &self.issuer,
            &self.scope.circuit_digest,
        )?;
        let requests: Vec<_> = prepared
            .iter()
            .map(|p| (p.inputs.as_slice(), p.proof.as_slice()))
            .collect();
        self.updates.verify_batch_before(&requests, deadline)
    }
    fn verify_anonymous(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        let verifier = match statement {
            ExtensionStatement::Deposit { .. } => &self.deposits,
            ExtensionStatement::Record { .. } => &self.records,
            ExtensionStatement::Update { .. } => return Err(Error::InvalidInput),
        };
        let deadline = std::time::Instant::now() + self.anonymous_timeout;
        let prepared = crate::prepared::extension_proofs(
            statement,
            proof,
            &self.issuer,
            &self.scope.circuit_digest,
        )?;
        let requests: Vec<_> = prepared
            .iter()
            .map(|p| (p.inputs.as_slice(), p.proof.as_slice()))
            .collect();
        verifier.verify_batch_before(&requests, deadline)
    }
}

#[cfg(test)]
#[path = "../tests/internal/verification_budget.rs"]
mod tests;
