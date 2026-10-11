//! Cached public R2 evidence, separate from fresh entry/device authorization.
use super::*;

/// Current native proof evidence for an already authenticated relying operation.
/// This has no challenge, device possession, admission or consumption authority.
/// It cannot be decoded, cloned or converted into a fresh `VerifiedRecord`.
pub struct VerifiedCachedRecord {
    record: Record,
    publication_digest: [u8; 32],
    checked_at: u64,
    valid_until: u64,
}
impl VerifiedCachedRecord {
    /// Exact original public record, with no private opening or request context.
    pub fn record(&self) -> &Record {
        &self.record
    }
    /// Actual final clock observation after successful native verification.
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    /// Exclusive publication/Charter/policy/record bound, not a liveness lease.
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

impl RecordVerifier {
    /// Reverify stored original public record/proof bytes using the real native
    /// R2 relation. Callers must separately authenticate the current device and
    /// existing attendance or reciprocal disclosure. This method cannot admit a
    /// new session: only `verify` checks a fresh, pending presentation context.
    pub fn verify_cached_record(
        &mut self,
        balance: &Balance,
        current: CharterBounds,
        expected_owner: &[u8; 32],
        record: &Record,
        proof: &str,
        clock: impl Fn() -> u64,
    ) -> Result<VerifiedCachedRecord, Error> {
        let now = self.view.observe_time(clock())?;
        let material = self.view.observe(balance, current, now)?;
        if record.owner != *expected_owner {
            return Err(Error::Admission);
        }
        self.verify_cached_at(balance, current, record, proof, &material, clock)
    }

    pub(super) fn verify_cached_at(
        &mut self,
        balance: &Balance,
        current: CharterBounds,
        record: &Record,
        proof: &str,
        material: &PublicVerifierMaterial,
        clock: impl Fn() -> u64,
    ) -> Result<VerifiedCachedRecord, Error> {
        let epoch = material
            .record_epoch
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        if &record.epoch != epoch {
            return Err(Error::Admission);
        }
        record.validate()?;
        czkp::record::verify_certificate(
            &epoch.issuer_key,
            &epoch.community,
            epoch.epoch,
            &record.blinded_leaf,
            &record.certificate,
        )?;
        // Apply the original bounded presentation encoding before allocation.
        if proof.is_empty() || proof.len() > 8 * 1024 * 1024 || proof.len() % 2 != 0 {
            return Err(Error::InvalidInput);
        }
        let proof = data_encoding::HEXLOWER
            .decode(proof.as_bytes())
            .map_err(|_| Error::InvalidInput)?;
        if proof.len() > material.policy.max_proof_bytes {
            return Err(Error::InvalidInput);
        }
        self.budget.check(&record.owner)?;
        let result = self.native.verify_anonymous(
            &ExtensionStatement::RecordEpoch {
                policy: material.extension_policy.clone(),
                record: record.clone(),
            },
            &proof,
        );
        let completed = self.view.observe_time(clock())?;
        result?;
        self.view.observe(balance, current, completed)?;
        Ok(VerifiedCachedRecord {
            record: record.clone(),
            publication_digest: Sha256::digest(balance.signed_bytes()).into(),
            checked_at: completed,
            valid_until: authority_until(balance, current, material, epoch),
        })
    }

    /// Check this actual native result against the actual current sealed view.
    /// The caller's serial authority guard must survive its final read/commit;
    /// this method alone neither authenticates nor spends a device operation.
    pub fn check_cached_current(
        &mut self,
        verified: &VerifiedCachedRecord,
        balance: &Balance,
        current: CharterBounds,
        now: u64,
    ) -> Result<(), Error> {
        self.check_cached_current_until(verified, balance, current, now, verified.valid_until)
    }

    pub(super) fn check_cached_current_until(
        &mut self,
        verified: &VerifiedCachedRecord,
        balance: &Balance,
        current: CharterBounds,
        now: u64,
        deadline: u64,
    ) -> Result<(), Error> {
        let now = self.view.observe_time(now)?;
        let material = self.view.observe(balance, current, now)?;
        if now < verified.checked_at {
            return Err(Error::ClockRollback);
        }
        if now >= verified.valid_until.min(deadline) {
            return Err(Error::Expired);
        }
        if <[u8; 32]>::from(Sha256::digest(balance.signed_bytes())) != verified.publication_digest
            || material.record_epoch.as_ref() != Some(&verified.record.epoch)
        {
            return Err(Error::PolicyMismatch);
        }
        Ok(())
    }
}
