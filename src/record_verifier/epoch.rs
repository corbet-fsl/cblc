//! Common authenticated epoch authority, without a member or proof verdict.
use super::*;

/// Current public epoch under the relying owner's native artifact pins. This
/// cannot authorize a member, consume a challenge, or replace an R2 proof.
/// Applications retain their current Charter lease across any use and recheck
/// the exact sealed publication after each await.
pub struct VerifiedRecordEpoch {
    epoch: Epoch,
    publication: [u8; 32],
    policy_digest: [u8; 32],
    valid_from: u64,
    checked_at: u64,
    valid_until: u64,
}
impl VerifiedRecordEpoch {
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }
    pub fn valid_from(&self) -> u64 {
        self.valid_from
    }
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

impl RecordVerifier {
    /// Authenticate the common descriptor only. Member admission must separately
    /// consume the existing genuine native record capability and device proof.
    pub fn current_epoch(
        &mut self,
        balance: &Balance,
        current: CharterBounds,
        now: u64,
    ) -> Result<VerifiedRecordEpoch, Error> {
        let now = self.view.observe_time(now)?;
        let material = self.view.observe(balance, current, now)?;
        let epoch = material
            .record_epoch
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let valid_until = authority_until(balance, current, &material, epoch);
        if now >= valid_until {
            return Err(Error::Expired);
        }
        Ok(VerifiedRecordEpoch {
            epoch: epoch.clone(),
            policy_digest: material.policy_digest,
            valid_from: epoch
                .starts_at
                .max(material.policy.account.policy_valid_from),
            publication: Sha256::digest(balance.signed_bytes()).into(),
            checked_at: now,
            valid_until,
        })
    }

    /// Recheck actual current sealed authority. Neither echoed request fields nor
    /// a longer refresh can extend the original capability's lifetime.
    pub fn check_epoch_current(
        &mut self,
        verified: &VerifiedRecordEpoch,
        balance: &Balance,
        current: CharterBounds,
        now: u64,
    ) -> Result<(), Error> {
        let now = self.view.observe_time(now)?;
        if now < verified.checked_at || now >= verified.valid_until {
            return Err(Error::Expired);
        }
        let material = self.view.observe(balance, current, now)?;
        let epoch = material
            .record_epoch
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        if material.policy_digest != verified.policy_digest
            || epoch != &verified.epoch
            || <[u8; 32]>::from(Sha256::digest(balance.signed_bytes())) != verified.publication
        {
            return Err(Error::PolicyMismatch);
        }
        if now >= authority_until(balance, current, &material, epoch) {
            return Err(Error::Expired);
        }
        Ok(())
    }
}
