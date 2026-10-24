//! A per-command owner capability, never a wire assertion or database adapter.
use super::*;
use std::sync::{Arc, Mutex};

/// Application-owned current authorization for a member operation.
///
/// Called inside the original storage transaction's logical decision while its
/// exclusive writer barrier is held. Re-read the real authentication, device,
/// legal and session owners at `observed`; do not acquire a second writer or
/// the request handler's outer lock. A bounded refusal is required if the
/// remaining read connection cannot be acquired. Retain actual owner leases
/// here so queued work and cancellation cannot outlive their authority.
pub trait CommitAuthority: Send + Sync {
    fn check(&self, observed: u64) -> Result<(), Error>;
    /// Called after `check(observed)` passed while the live clock moved on to
    /// `now`, under the same writer barrier. Return true when a boundary of this
    /// authority's schedule (an epoch or period transition, a deadline) lies in
    /// `(observed, now]`; the operation then refuses and restarts fresh. The
    /// default knows no schedule and treats every second as a boundary.
    fn boundary_crossed(&self, observed: u64, now: u64) -> Result<bool, Error> {
        Ok(now != observed)
    }
    /// The member's current device lineage (the door's device registry), when this authority
    /// speaks for a member. Every account update asks it for a `CurrentDevice` witness; the
    /// default knows no lineage, so an authority without one refuses all member updates.
    fn lineage(&self) -> Option<&dyn crate::current_device::CurrentLineage> {
        None
    }
}

enum State {
    Idle,
    Active(Arc<dyn CommitAuthority>),
    Poisoned,
}

#[derive(Clone)]
pub(crate) struct AuthorityScope(Arc<Mutex<State>>);

pub(crate) struct AuthorityGuard(AuthorityScope);

impl AuthorityScope {
    pub(crate) fn wrap(store: impl AccountStorage + 'static) -> (Box<dyn AccountStorage>, Self) {
        let scope = Self(Arc::new(Mutex::new(State::Idle)));
        (
            Box::new(AuthorizedStore {
                store,
                scope: scope.clone(),
            }),
            scope,
        )
    }

    pub(crate) fn enter(
        &self,
        authority: Arc<dyn CommitAuthority>,
    ) -> Result<AuthorityGuard, Error> {
        let mut state = self.0.lock().map_err(|_| Error::Storage)?;
        if !matches!(*state, State::Idle) {
            return Err(Error::Storage);
        }
        *state = State::Active(authority);
        Ok(AuthorityGuard(self.clone()))
    }

    pub(crate) fn current(&self) -> Result<Option<Arc<dyn CommitAuthority>>, Error> {
        match &*self.0.lock().map_err(|_| Error::Storage)? {
            State::Idle => Ok(None),
            State::Active(authority) => Ok(Some(authority.clone())),
            State::Poisoned => Err(Error::Storage),
        }
    }
}

impl Drop for AuthorityGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.0.lock() {
            *state = if std::thread::panicking() {
                State::Poisoned
            } else {
                State::Idle
            };
        }
    }
}

struct AuthorizedStore<S> {
    store: S,
    scope: AuthorityScope,
}

impl<S: AccountStorage> AccountStorage for AuthorizedStore<S> {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        // Capture once. A later queued command can never replace this owner.
        let authority = self.scope.current()?;
        let transaction = self.store.transaction()?;
        Ok(Transaction::new(Box::new(AuthorizedTransaction {
            transaction: transaction.0,
            authority,
        })))
    }
}

struct AuthorizedTransaction<'a> {
    transaction: Box<dyn AtomicTransaction + 'a>,
    authority: Option<Arc<dyn CommitAuthority>>,
}

impl AtomicTransaction for AuthorizedTransaction<'_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.transaction.get(key)
    }
    fn current_range(
        &mut self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<CurrentRecord>, Error> {
        self.transaction.current_range(start, end, limit)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.transaction.put(key, value)
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.transaction.delete(key)
    }
    fn commit(self: Box<Self>) -> Result<(), Error> {
        if self.authority.is_some() {
            return Err(Error::Admission);
        }
        self.transaction.commit()
    }
    fn commit_before(self: Box<Self>, deadline: &CommitDeadline<'_>) -> Result<(), Error> {
        let scoped = scoped_deadline(deadline, self.authority.as_deref());
        self.transaction.commit_before(&scoped)?;
        deadline.observed.set(scoped.observed.get());
        // A host violating the required decision callback has an uncertain
        // outcome. Never misreport a successfully persisted operation as expiry.
        if !scoped.authorized.get() {
            return Err(Error::Storage);
        }
        Ok(())
    }
    fn rollback(self: Box<Self>) -> Result<(), Error> {
        // Internal prechecks may abandon a transaction without releasing any
        // member result. Authenticated reads use rollback_before instead.
        self.transaction.rollback()
    }
    fn rollback_before(self: Box<Self>, deadline: &CommitDeadline<'_>) -> Result<(), Error> {
        let scoped = scoped_deadline(deadline, self.authority.as_deref());
        self.transaction.rollback_before(&scoped)?;
        deadline.observed.set(scoped.observed.get());
        if !scoped.authorized.get() {
            return Err(Error::Storage);
        }
        Ok(())
    }
}

fn scoped_deadline<'a>(
    deadline: &'a CommitDeadline<'_>,
    authority: Option<&'a dyn CommitAuthority>,
) -> CommitDeadline<'a> {
    CommitDeadline {
        clock: deadline.clock,
        observed: std::cell::Cell::new(deadline.observed.get()),
        expires_at: deadline.expires_at,
        authority: authority.or(deadline.authority),
        authorized: std::cell::Cell::new(false),
    }
}

#[cfg(test)]
mod tests;
