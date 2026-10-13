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
/// Every tag ever posted. A consumed tag stays here so a replayed presentation cannot post twice.
const POSTED: u8 = 13;
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

    /// Post one obligation tag after its unlinkable presentation has been verified.
    /// A tag that is already waiting is refused, so a presentation posts exactly once.
    pub fn post_obligation(&mut self, tag: &[u8; 32]) -> Result<(), Error> {
        czkp::field(tag, true)?;
        if tag == &[0; 32] {
            return Err(Error::InvalidInput);
        }
        let mut transaction = self.connection.transaction()?;
        if waiting(&mut transaction, tag)?
            || transaction.get::<bool>(&key(POSTED, &[tag]))?.unwrap_or(false)
        {
            return Err(Error::Replay);
        }
        transaction.put(&key(POSTED, &[tag]), &true)?;
        transaction.put(&key(MAILBOX, &[tag]), &true)?;
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
        let crate::extensions::VoucherPurpose::Post { tag } = presentation.purpose else {
            return Err(Error::InvalidInput);
        };
        self.check_voucher_epoch(presentation, proof, expected_binding, clock)?;
        self.post_obligation(&tag)
    }

    /// Whether an obligation tag is waiting; the only read a poller needs.
    pub fn obligation_waiting(&mut self, tag: &[u8; 32]) -> Result<bool, Error> {
        let mut transaction = self.connection.transaction()?;
        let waiting = waiting(&mut transaction, tag)?;
        transaction.rollback()?;
        Ok(waiting)
    }
}
