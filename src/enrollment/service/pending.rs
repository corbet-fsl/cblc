//! Original durable frozen context and opaque prepare/commit acknowledgment.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Frozen {
    pub(super) publication: EnrollmentPublication,
    pub(super) installed: bool,
    pub(super) checked_at: u64,
    pub(super) policy_epoch: u64,
    pub(super) passport_policy_digest: String,
}

/// Exact durable publisher preparation retaining its real source owner over
/// forwarding. Cloned public bytes confer no installation authority.
pub struct PendingCheckpoint {
    config: EnrollmentConfig,
    frozen: Frozen,
    authority: Arc<dyn CommitAuthority>,
}
impl PendingCheckpoint {
    pub(super) fn new(
        config: EnrollmentConfig,
        frozen: Frozen,
        authority: Arc<dyn CommitAuthority>,
    ) -> Self {
        Self {
            config,
            frozen,
            authority,
        }
    }
    /// Exact original signed common publication, without its retained guards.
    pub fn publication(&self) -> &EnrollmentPublication {
        &self.frozen.publication
    }
    pub(super) fn same_config(&self, config: &EnrollmentConfig) -> bool {
        &self.config == config
    }
    pub(crate) fn correspondence(&self) -> Result<([u8; 32], [u8; 32]), Error> {
        correspondence(&self.config, &self.frozen)
    }
}
pub(super) fn correspondence(
    config: &EnrollmentConfig,
    frozen: &Frozen,
) -> Result<([u8; 32], [u8; 32]), Error> {
    Ok((
        Sha256::digest(
            serde_json::to_vec(&(
                &frozen.publication,
                frozen.checked_at,
                frozen.policy_epoch,
                &frozen.passport_policy_digest,
            ))
            .map_err(|_| Error::Storage)?,
        )
        .into(),
        Sha256::digest(serde_json::to_vec(config).map_err(|_| Error::Storage)?).into(),
    ))
}
impl PendingCheckpoint {
    pub(crate) fn validate_install(
        &self,
        community: &str,
        digest: &str,
        operator: &[u8; 32],
        period: u64,
        now: u64,
    ) -> Result<(), Error> {
        if self.config.community_id != community
            || self.config.policy_digest != digest
            || &self.config.operator_public_key != operator
            || self.config.checkpoint_period_seconds != period
        {
            return Err(Error::PolicyMismatch);
        }
        validate(&self.config, self.publication())?;
        if now == 0 || now > czkp::MAX_INTEGER {
            return Err(Error::ClockRollback);
        }
        if now < self.frozen.checked_at
            || now < self.publication().not_before
            || now >= self.publication().expires_at
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub(crate) fn source_authority(&self) -> Arc<dyn CommitAuthority> {
        self.authority.clone()
    }
    // Only the actual ledger's successful slot CAS produces this receipt.
    pub(crate) fn installed(self) -> InstalledCheckpoint {
        InstalledCheckpoint(self)
    }
}

/// Actual accounting-owner acknowledgment of exactly one frozen object.
/// No public constructor, wire format, clone, or signature-only route exists.
pub struct InstalledCheckpoint(pub(super) PendingCheckpoint);
impl InstalledCheckpoint {
    /// Original acknowledged bytes, never a renewed interval or member grant.
    pub fn publication(&self) -> &EnrollmentPublication {
        self.0.publication()
    }
}

pub(super) fn validate(config: &EnrollmentConfig, p: &EnrollmentPublication) -> Result<(), Error> {
    config.validate()?;
    let start = p
        .slot
        .checked_mul(config.checkpoint_period_seconds)
        .ok_or(Error::InvalidInput)?;
    let end = p
        .slot
        .checked_add(1)
        .and_then(|slot| slot.checked_mul(config.checkpoint_period_seconds))
        .filter(|end| *end <= czkp::MAX_INTEGER)
        .ok_or(Error::InvalidInput)?;
    if p.community_id != config.community_id
        || p.policy_digest != config.policy_digest
        || p.not_before != start
        || p.expires_at != end
    {
        return Err(Error::PolicyMismatch);
    }
    czkp::field(&p.root, true)?;
    p.verify_signature(&config.operator_public_key)?;
    if serde_json::to_vec(p).map_err(|_| Error::Storage)?.len() as u64
        > config.max_publication_bytes
    {
        return Err(Error::Capacity);
    }
    Ok(())
}

// This historical-only reconstruction never creates current admission seals.
// The configured operator signature and original durable context are required;
// a new slot always uses the host's independently CURRENT Policy expectations.
pub(super) fn authenticate_frozen(
    frozen: &Frozen,
    trust: &crate::admission::AdmissionTrust,
    now: u64,
) -> Result<(), Error> {
    let p = &frozen.publication;
    if frozen.checked_at < p.not_before
        || frozen.checked_at >= p.expires_at
        || now < frozen.checked_at
        || frozen.policy_epoch == 0
        || frozen.policy_epoch > czkp::MAX_INTEGER
    {
        return Err(Error::Admission);
    }
    czkp::decode::<32>(&frozen.passport_policy_digest).map_err(|_| Error::Admission)?;
    let values = p
        .delegations
        .iter()
        .map(|value| {
            if value.entry.expires_at < p.expires_at {
                return Err(Error::Admission);
            }
            super::super::delegation::verify_historical(
                &value.delegation,
                ExpectedAdmission {
                    trust,
                    policy_epoch: frozen.policy_epoch,
                    passport_policy_digest: &frozen.passport_policy_digest,
                },
                frozen.checked_at,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tree = EnrollmentTree::from_historical(&values)?;
    if tree.root() != p.root {
        return Err(Error::Admission);
    }
    Ok(())
}

pub(super) const START: &[u8] = b"enrollment/pending/";
pub(super) const END: &[u8] = b"enrollment/pending0";
pub(super) fn key(slot: u64) -> Vec<u8> {
    let mut key = START.to_vec();
    key.extend_from_slice(&slot.to_be_bytes());
    key
}
pub(super) fn retained(
    tx: &mut Transaction<'_>,
    config: &EnrollmentConfig,
) -> Result<Vec<(Vec<u8>, Frozen)>, Error> {
    let rows = tx.current_range::<Frozen>(START, END, config.max_retained_slots + 1)?;
    if rows.len() > config.max_retained_slots as usize {
        return Err(Error::Storage);
    }
    let mut total = 0_u64;
    for (stored_key, value) in &rows {
        validate(config, &value.publication)?;
        if stored_key != &key(value.publication.slot) {
            return Err(Error::Storage);
        }
        total = total
            .checked_add(
                serde_json::to_vec(&value.publication)
                    .map_err(|_| Error::Storage)?
                    .len() as u64,
            )
            .ok_or(Error::Storage)?;
    }
    if total > config.max_publication_bytes {
        return Err(Error::Storage);
    }
    Ok(rows)
}
pub(super) fn persist(
    tx: &mut Transaction<'_>,
    config: &EnrollmentConfig,
    frozen: &Frozen,
) -> Result<(), Error> {
    let p = &frozen.publication;
    validate(config, p)?;
    let mut rows = retained(tx, config)?;
    let current = key(p.slot);
    if rows.iter().any(|(_, v)| v.publication.slot >= p.slot) {
        return Err(Error::Replay);
    }
    rows.push((current.clone(), frozen.clone()));
    let mut total = rows
        .iter()
        .map(|(_, r)| {
            serde_json::to_vec(&r.publication)
                .map(|b| b.len() as u64)
                .map_err(|_| Error::Storage)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<u64>();
    let mut count = rows.len();
    for (stored_key, value) in rows {
        if stored_key != current
            && (count > config.max_retained_slots as usize || total > config.max_publication_bytes)
        {
            total -= serde_json::to_vec(&value.publication)
                .map_err(|_| Error::Storage)?
                .len() as u64;
            count -= 1;
            tx.delete(&stored_key)?;
        }
    }
    tx.put(&current, frozen)
}
