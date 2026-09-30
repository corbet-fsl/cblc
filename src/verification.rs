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

/// Two independently bounded process pools. Anonymous deposits and record checks
/// cannot occupy the pool reserved for authenticated account updates.
pub struct ProcessExtensionVerifier {
    updates: cvfy::ProcessVerifier,
    anonymous: cvfy::ProcessVerifier,
}
impl ProcessExtensionVerifier {
    pub fn new(
        updates: cvfy::ProcessVerifierConfig,
        anonymous: cvfy::ProcessVerifierConfig,
    ) -> Result<Self, Error> {
        if updates.scope != anonymous.scope
            || updates.script != anonymous.script
            || updates.artifact_config != anonymous.artifact_config
        {
            return Err(Error::PolicyMismatch);
        }
        Ok(Self {
            updates: cvfy::ProcessVerifier::new(updates)?,
            anonymous: cvfy::ProcessVerifier::new(anonymous)?,
        })
    }
}
impl ExtensionVerifier for ProcessExtensionVerifier {
    fn scope(&self) -> AccountProofScope {
        self.updates.scope()
    }
    fn verify(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        self.updates.verify(statement, proof)
    }
    fn verify_anonymous(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        self.anonymous.verify(statement, proof)
    }
}
