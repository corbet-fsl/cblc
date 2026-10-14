//! Voucher accounting at the ledger: role classes and the bond-addressed mailbox.
//!
//! The ledger never learns which two members share a bond. It sees opaque tags: a
//! tag appears when an unlinkable presentation posts it, and disappears with the one
//! account update that consumes it. Roles are the ledger's own record of each owner's
//! class (member, admin, root), set by the community's authority, and are the only
//! source of the role class in epoch leaves and in the admission proof.
use super::*;
use crate::extensions::Effect;

const ROLE: u8 = 11;
const MAILBOX: u8 = 12;
/// Every tag posted within the retention window, valued by its posting time. A consumed tag
/// stays here so a replayed presentation cannot post twice, until it ages out.
const POSTED: u8 = 13;
/// Posting index keyed by (posting time, tag), used to drop aged rows in bounded batches.
const POSTED_AGE: u8 = 15;
/// Retention of posted tags and of unconsumed mailbox rows: the rulebook setting `K`, in days.
/// A re-post after pruning costs the vouchee a full proof and a budget unit, and lands as
/// mailbox garbage the sponsor never consumes (the sponsor circuit refuses a repeated
/// sequence number and a second success), so retention only bounds storage.
pub const DEFAULT_RETENTION_DAYS: u64 = 90;
/// Smallest and largest accepted retention (days).
pub const RETENTION_DAYS_BOUNDS: (u64, u64) = (7, 730);
/// Reserved issue units, keyed by (epoch, nullifier). Only the current epoch's presentations
/// are accepted, so rows of earlier epochs can never matter again and are pruned.
const ISSUED: u8 = 14;
/// Older-epoch rows removed per spend, so pruning needs no scheduler.
const PRUNE_BATCH: u32 = 64;
/// Role classes: member, admin, root (czkp::voucher).
pub const MAX_ROLE: u8 = 2;

/// The recorded role class of an owner; members unless set otherwise.
pub(crate) fn role_of(tx: &mut Transaction<'_>, owner: &[u8; 32]) -> Result<u8, Error> {
    Ok(tx.get::<u8>(&key(ROLE, &[owner]))?.unwrap_or(0))
}

/// Whether a tag is waiting in the mailbox.
pub(crate) fn waiting(tx: &mut Transaction<'_>, tag: &[u8; 32]) -> Result<bool, Error> {
    Ok(tx.get::<bool>(&key(MAILBOX, &[tag]))?.unwrap_or(false))
}

/// Refuse early, before any expensive verification, an effect the ledger cannot honour.
pub(crate) fn precheck(
    tx: &mut Transaction<'_>,
    owner: &[u8; 32],
    effect: &Effect,
) -> Result<(), Error> {
    match effect {
        Effect::Admit { role } => {
            if *role > MAX_ROLE || *role != role_of(tx, owner)? {
                return Err(Error::PolicyMismatch);
            }
        }
        Effect::Consume { obligation } => {
            if !waiting(tx, obligation)? {
                return Err(Error::Admission);
            }
        }
        Effect::Update | Effect::Change { .. } => {}
    }
    Ok(())
}

/// Apply the effect inside the accepting transaction: a consumed tag leaves the mailbox
/// together with the state change that used it, so it can be used exactly once.
pub(crate) fn apply(
    tx: &mut Transaction<'_>,
    owner: &[u8; 32],
    effect: &Effect,
) -> Result<(), Error> {
    precheck(tx, owner, effect)?;
    if let Effect::Consume { obligation } = effect {
        tx.delete(&key(MAILBOX, &[obligation]))?;
    }
    Ok(())
}

fn issued_key(epoch: u64, nullifier: &[u8; 32]) -> Vec<u8> {
    key(ISSUED, &[&epoch.to_be_bytes(), nullifier])
}

fn issue_units(
    presentation: &crate::extensions::VoucherPresentation,
) -> Result<&[[u8; 32]], Error> {
    let crate::extensions::VoucherPurpose::Issue { nullifiers, .. } = &presentation.purpose else {
        return Err(Error::InvalidInput);
    };
    Ok(nullifiers)
}

/// Refuse a presentation whose units were already spent in its epoch.
pub(crate) fn check_unspent(
    tx: &mut Transaction<'_>,
    presentation: &crate::extensions::VoucherPresentation,
) -> Result<(), Error> {
    for nullifier in issue_units(presentation)? {
        if tx
            .get::<bool>(&issued_key(presentation.epoch.epoch, nullifier))?
            .unwrap_or(false)
        {
            return Err(Error::Replay);
        }
    }
    Ok(())
}

/// Record every unit of an already verified issue presentation, atomically with the
/// caller's transaction, and drop a bounded batch of rows from earlier epochs.
pub(crate) fn spend_units(
    tx: &mut Transaction<'_>,
    presentation: &crate::extensions::VoucherPresentation,
) -> Result<(), Error> {
    check_unspent(tx, presentation)?;
    let epoch = presentation.epoch.epoch;
    for nullifier in issue_units(presentation)? {
        tx.put(&issued_key(epoch, nullifier), &true)?;
    }
    let old: Vec<(Vec<u8>, bool)> = tx.current_range(
        &key(ISSUED, &[&0u64.to_be_bytes()]),
        &key(ISSUED, &[&epoch.to_be_bytes()]),
        PRUNE_BATCH,
    )?;
    for (row, _) in old {
        tx.delete(&row)?;
    }
    Ok(())
}

/// Drop a bounded batch of posted tags older than the retention horizon, together with
/// their unconsumed mailbox rows (the mailbox TTL).
fn prune_aged(tx: &mut Transaction<'_>, horizon: u64) -> Result<(), Error> {
    if horizon == 0 {
        return Ok(());
    }
    let aged: Vec<(Vec<u8>, bool)> = tx.current_range(
        &key(POSTED_AGE, &[&0u64.to_be_bytes()]),
        &key(POSTED_AGE, &[&horizon.to_be_bytes()]),
        PRUNE_BATCH,
    )?;
    for (row, _) in aged {
        // The tag is the last 32 bytes of the row key.
        let tag: [u8; 32] = row[row.len() - 32..]
            .try_into()
            .map_err(|_| Error::InvalidInput)?;
        tx.delete(&key(MAILBOX, &[&tag]))?;
        tx.delete(&key(POSTED, &[&tag]))?;
        tx.delete(&row)?;
    }
    Ok(())
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Record an owner's role class. Only the community's authority may call this;
    /// it is never reachable from a member request. The class becomes visible to the
    /// owner's proofs at once and to epoch leaves at the next freeze.
    pub fn set_role(&mut self, owner: &[u8; 32], role: u8) -> Result<(), Error> {
        if role > MAX_ROLE || owner == &[0; 32] {
            return Err(Error::InvalidInput);
        }
        let mut transaction = self.connection.transaction()?;
        if role == 0 {
            transaction.delete(&key(ROLE, &[owner]))?;
        } else {
            transaction.put(&key(ROLE, &[owner]), &role)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// The recorded role class of an owner.
    pub fn role(&mut self, owner: &[u8; 32]) -> Result<u8, Error> {
        let mut transaction = self.connection.transaction()?;
        let role = role_of(&mut transaction, owner)?;
        transaction.rollback()?;
        Ok(role)
    }

    /// The retention `K` in days for posted tags and unconsumed mailbox rows.
    pub fn obligation_retention_days(&self) -> u64 {
        self.retention_days
    }

    /// Set the retention `K` (a rulebook value, bounded to 7..=730 days; default 90).
    pub fn set_obligation_retention_days(&mut self, days: u64) -> Result<(), Error> {
        if !(RETENTION_DAYS_BOUNDS.0..=RETENTION_DAYS_BOUNDS.1).contains(&days) {
            return Err(Error::InvalidInput);
        }
        self.retention_days = days;
        Ok(())
    }

    /// Post one obligation tag after its unlinkable presentation has been verified.
    /// A tag that is already waiting is refused, so a presentation posts exactly once.
    /// The posting time is the latest time this handle has observed.
    pub fn post_obligation(&mut self, tag: &[u8; 32]) -> Result<(), Error> {
        let now = self.observed_time.load(Ordering::Acquire).max(1);
        self.post_obligation_at(tag, now)
    }

    /// Post a tag at an explicit time (the host's verified clock or the presentation time).
    pub fn post_obligation_at(&mut self, tag: &[u8; 32], now: u64) -> Result<(), Error> {
        czkp::field(tag, true)?;
        if tag == &[0; 32] || now == 0 || now > czkp::MAX_INTEGER {
            return Err(Error::InvalidInput);
        }
        let horizon = now.saturating_sub(self.retention_days * 86_400);
        let mut transaction = self.connection.transaction()?;
        if waiting(&mut transaction, tag)?
            || transaction.get::<u64>(&key(POSTED, &[tag]))?.is_some()
        {
            return Err(Error::Replay);
        }
        transaction.put(&key(POSTED, &[tag]), &now)?;
        transaction.put(&key(POSTED_AGE, &[&now.to_be_bytes(), tag]), &true)?;
        transaction.put(&key(MAILBOX, &[tag]), &true)?;
        prune_aged(&mut transaction, horizon)?;
        transaction.commit()?;
        Ok(())
    }

    /// Verify a `Post` presentation against the current epoch, then post its tag. The
    /// proof already shows that the hidden member holds the bond and the right to post.
    pub fn post_presented_obligation(
        &mut self,
        presentation: &crate::extensions::VoucherPresentation,
        proof: &[u8],
        expected_binding: &[u8; 32],
        clock: impl Fn() -> u64,
    ) -> Result<(), Error> {
        let crate::extensions::VoucherPurpose::Post { tag } = presentation.purpose.clone() else {
            return Err(Error::InvalidInput);
        };
        self.check_voucher_epoch(presentation, proof, expected_binding, clock)?;
        self.post_obligation_at(&tag, presentation.now)
    }

    /// Whether an obligation tag is waiting; the only read a poller needs.
    pub fn obligation_waiting(&mut self, tag: &[u8; 32]) -> Result<bool, Error> {
        let mut transaction = self.connection.transaction()?;
        let waiting = waiting(&mut transaction, tag)?;
        transaction.rollback()?;
        Ok(waiting)
    }
}
