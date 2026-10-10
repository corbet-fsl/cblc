//! Native R2 verification for relying applications, without issuer storage.
//!
//! The application supplies its current authenticated Charter view and the
//! independently configured publication period. A signed Rulebook projection
//! of that period remains an application integration prerequisite; the submitted
//! descriptor must never choose it. Successful verification does not consume a
//! challenge or admit a member. The caller must atomically consume its original
//! pending challenge with the resulting presence, rechecking current authority
//! after every intervening await and at the commit boundary.
use crate::{
    Error,
    accounting::AccountProofScope,
    artifacts::ArtifactBinding,
    extensions::{ExtensionStatement, ExtensionVerifier, RecordContext},
    publication::PublicVerifierMaterial,
    verification::{Budget, ExtensionLimits, NativeExtensionVerifier},
};
use cbcn::balance::Balance;
use czkp::record::{Epoch, Presentation, Record};
use sha2::{Digest, Sha256};

/// Trusted bounds from the application's current verified Charter, in seconds.
/// These must not be copied from the submitted presentation or decoded material.
#[derive(Clone, Copy)]
pub struct CharterBounds {
    /// Current policy epoch from the application's authenticated Charter.
    pub policy_epoch: u64,
    /// Exclusive expiry of that authenticated Charter view, in Unix seconds.
    pub valid_until: u64,
}

/// A native proof result, not an admission or challenge-consumption receipt.
/// There is no wire decoder, unchecked constructor, or clonable authority.
pub struct VerifiedRecord {
    record: Record,
    context: RecordContext,
    publication_digest: [u8; 32],
    checked_at: u64,
    record_until: u64,
    commit_until: u64,
}
impl VerifiedRecord {
    /// Public record statement checked by the native R2 relation.
    pub fn record(&self) -> &Record {
        &self.record
    }
    /// Independently expected context authenticated by the presentation binding.
    pub fn context(&self) -> &RecordContext {
        &self.context
    }
    /// Completion wall-clock sample, in Unix seconds.
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    /// Exclusive bound of this record's checked publication authority. This is
    /// neither an attendance lease nor a promise that Charter will stay current.
    pub fn record_until(&self) -> u64 {
        self.record_until
    }
    /// Exclusive bound for committing this fresh challenge. It cannot extend
    /// the record, publication, Charter, or original challenge lifetime.
    pub fn commit_until(&self) -> u64 {
        self.commit_until
    }
}

/// One relying application's retained native artifact pins and observation floors.
/// Keep this owner alive across requests; application restart/fleet floors remain
/// the current Charter owner's responsibility. No member history is retained.
pub struct RecordVerifier {
    native: NativeExtensionVerifier,
    budget: Budget,
    view: View,
}
impl RecordVerifier {
    /// Retain host-configured community, epoch period, artifact pins and limits.
    /// The native artifact group must include the original R2 verifying key.
    pub fn new(
        community: String,
        period_seconds: u64,
        native: NativeExtensionVerifier,
        limits: ExtensionLimits,
    ) -> Result<Self, Error> {
        if !crate::admission::scope(&community)
            || period_seconds == 0
            || period_seconds > czkp::MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        native.require_record_epoch()?;
        let budget = Budget::new(&community, limits)?;
        let view = View {
            community,
            period_seconds,
            scope: native.scope(),
            artifacts: native.artifact_binding.clone(),
            observed_time: 0,
            policy_epoch: 0,
            balance: None,
            epoch: None,
        };
        Ok(Self {
            native,
            budget,
            view,
        })
    }

    /// Verify against the current sealed publication and trusted Charter bounds.
    /// Owner and context come from the application's original pending operation.
    /// The clock is sampled before and after native work; success does not
    /// consume that operation or guarantee current authority at a later commit.
    pub fn verify(
        &mut self,
        balance: &Balance,
        current: CharterBounds,
        expected_owner: &[u8; 32],
        expected: &RecordContext,
        presentation: &Presentation,
        clock: impl Fn() -> u64,
    ) -> Result<VerifiedRecord, Error> {
        let now = self.view.observe_time(clock())?;
        let material = self.view.observe(balance, current, now)?;
        let epoch = material
            .record_epoch
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        if expected.expires_at > now.saturating_add(material.policy.max_authorization_seconds) {
            return Err(Error::Expired);
        }
        presentation.check_binding(expected, epoch, expected_owner, now)?;
        let proof = data_encoding::HEXLOWER
            .decode(presentation.proof.as_bytes())
            .map_err(|_| Error::InvalidInput)?;
        if proof.len() > material.policy.max_proof_bytes {
            return Err(Error::InvalidInput);
        }
        self.budget.check(expected_owner)?;
        let verified = self.native.verify_anonymous(
            &ExtensionStatement::RecordEpoch {
                policy: material.extension_policy.clone(),
                record: presentation.record.clone(),
            },
            &proof,
        );
        let completed = self.view.observe_time(clock())?;
        verified?;
        self.view.observe(balance, current, completed)?;
        presentation.check_binding(expected, epoch, expected_owner, completed)?;
        let record_until = authority_until(balance, current, &material, epoch);
        Ok(VerifiedRecord {
            record: presentation.record.clone(),
            context: expected.clone(),
            publication_digest: Sha256::digest(balance.signed_bytes()).into(),
            checked_at: completed,
            record_until,
            commit_until: record_until.min(expected.expires_at),
        })
    }

    /// Recheck against the actual current sealed publication, not echoed fields.
    /// Call after acquiring the application's current Charter/pending-operation
    /// guard. That guard must remain current through the atomic storage commit.
    pub fn check_current(
        &mut self,
        verified: &VerifiedRecord,
        balance: &Balance,
        current: CharterBounds,
        now: u64,
    ) -> Result<(), Error> {
        let now = self.view.observe_time(now)?;
        let material = self.view.observe(balance, current, now)?;
        if now < verified.checked_at {
            return Err(Error::ClockRollback);
        }
        if now >= verified.commit_until {
            return Err(Error::Expired);
        }
        if <[u8; 32]>::from(Sha256::digest(balance.signed_bytes())) != verified.publication_digest
            || material.record_epoch.as_ref() != Some(&verified.record.epoch)
        {
            return Err(Error::PolicyMismatch);
        }
        // Re-observation already checks all shorter current publication and
        // Charter deadlines. A longer refresh cannot extend the sealed result.
        Ok(())
    }
}

fn authority_until(
    balance: &Balance,
    current: CharterBounds,
    material: &PublicVerifierMaterial,
    epoch: &Epoch,
) -> u64 {
    balance
        .valid_until()
        .min(current.valid_until)
        .min(material.policy.account.policy_valid_until)
        .min(epoch.expires_at)
}

struct View {
    community: String,
    period_seconds: u64,
    scope: AccountProofScope,
    artifacts: ArtifactBinding,
    observed_time: u64,
    policy_epoch: u64,
    balance: Option<Balance>,
    epoch: Option<Epoch>,
}
impl View {
    fn observe_time(&mut self, now: u64) -> Result<u64, Error> {
        if now == 0 || now > czkp::MAX_INTEGER || now < self.observed_time {
            return Err(Error::ClockRollback);
        }
        self.observed_time = now;
        Ok(now)
    }

    fn observe(
        &mut self,
        balance: &Balance,
        current: CharterBounds,
        now: u64,
    ) -> Result<PublicVerifierMaterial, Error> {
        if current.policy_epoch == 0
            || current.policy_epoch > czkp::MAX_INTEGER
            || current.valid_until > czkp::MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        if now >= current.valid_until || now >= balance.valid_until() {
            return Err(Error::Expired);
        }
        let material: PublicVerifierMaterial =
            serde_json::from_slice(balance.payload()).map_err(|_| Error::InvalidInput)?;
        material.validate_at(&self.community, now)?;
        if material.policy_epoch != current.policy_epoch
            || material.revision != balance.revision()
            || material.proof_scope != self.scope
            || material.manifest_sha256 != self.artifacts.manifest_sha256
            || material.certificate_key.as_slice() != self.artifacts.certificate_key
        {
            return Err(Error::PolicyMismatch);
        }
        if let Some(previous) = &self.balance {
            balance
                .check_successor(previous)
                .map_err(|_| Error::Replay)?;
        }
        if current.policy_epoch < self.policy_epoch {
            return Err(Error::Replay);
        }
        // Even a newer signed publication withdrawing the optional epoch must
        // fence older material. Keep the last epoch floor across such withdrawal.
        self.balance = Some(balance.clone());
        self.policy_epoch = current.policy_epoch;
        let epoch = material
            .record_epoch
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let community = Sha256::digest(self.community.as_bytes()).into();
        epoch.validate(&community, self.period_seconds)?;
        if let Some(previous) = &self.epoch {
            epoch.check_successor(previous, self.period_seconds)?;
        }
        epoch.check_time(now)?;
        self.epoch = Some(epoch.clone());
        Ok(material)
    }
}

#[cfg(test)]
#[path = "../tests/internal/record_verifier.rs"]
mod tests;
