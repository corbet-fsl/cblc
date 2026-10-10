//! Caller-owned atomic accounting state. The library opens no databases.
use crate::Error;
pub use cssr::{CurrentRecord, MemoryStore};
use serde::{Serialize, de::DeserializeOwned};
/// A store that supplies atomic issuer transactions.
pub trait AccountStorage: Send {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error>;
}
/// Atomic host transaction. Reads and writes share one serializable transaction.
/// Drop without commit must roll back. A successful commit atomically updates
/// all keys under the host's declared durability; uncertain outcomes require
/// exact idempotent retry. The RAM implementation has no restart durability.
/// The keys contain only selected accounting commitments and replay metadata,
/// never raw provider payloads, balances, counterparties or holder openings.
pub trait AtomicTransaction {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    /// Read ordered current key/value pairs in the half-open range under this
    /// same transaction. Accept a positive bound up to 2^20 + 1; the final row
    /// is the original epoch freeze's overflow sentinel, not history pagination.
    /// Existing hosts refuse until they implement a complete bounded snapshot.
    fn current_range(
        &mut self,
        _start: &[u8],
        _end: &[u8],
        _limit: u32,
    ) -> Result<Vec<CurrentRecord>, Error> {
        Err(Error::UnsupportedCapability)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error>;
    fn delete(&mut self, key: &[u8]) -> Result<(), Error>;
    fn commit(self: Box<Self>) -> Result<(), Error>;
    /// Obtain `deadline.commit_record()` after blocking business work, at the
    /// logical commit decision while the write lock is held. Include that clock
    /// record in the same atomic commit; failed checks discard staged changes.
    /// There is no default: each host owns this boundary. Physical persistence
    /// of the chosen state and clock record may finish after that decision.
    fn commit_before(self: Box<Self>, deadline: &CommitDeadline<'_>) -> Result<(), Error>;
    fn rollback(self: Box<Self>) -> Result<(), Error>;
}

/// A live trusted clock and exclusive authority window for one atomic operation.
/// The host checks this inside its serialized commit decision, not before waiting
/// for locks or writing staged data. It cannot be reduced to a sampled timestamp.
pub struct CommitDeadline<'a> {
    clock: &'a dyn Fn() -> u64,
    observed: std::cell::Cell<u64>,
    expires_at: u64,
}
impl<'a> CommitDeadline<'a> {
    /// Construct a deadline from the caller's clock and already validated bounds.
    pub fn new(clock: &'a dyn Fn() -> u64, observed: u64, expires_at: u64) -> Self {
        Self {
            clock,
            observed: std::cell::Cell::new(observed),
            expires_at,
        }
    }
    /// Resample the trusted clock. Check this immediately at the host's commit
    /// decision, after any potentially blocking pre-commit work.
    pub fn check(&self) -> Result<u64, Error> {
        let now = (self.clock)();
        if now == 0 || now < self.observed.get() || now > czkp::MAX_INTEGER {
            return Err(Error::ClockRollback);
        }
        if now >= self.expires_at {
            return Err(Error::Expired);
        }
        self.observed.set(now);
        Ok(now)
    }

    /// Select the logical commit time and its required opaque storage record.
    /// The host must stage this record under the same exclusive ownership and
    /// commit it atomically with the already validated business state. Do no
    /// further business work after this decision; only its physical persistence
    /// and completion remain. The record preserves the actual observation for
    /// another ledger handle or a restart, rather than an earlier sampled time.
    pub fn commit_record(&self) -> Result<(&'static [u8], Vec<u8>), Error> {
        let now = self.check()?;
        Ok((b"clock", now.to_string().into_bytes()))
    }
}

// Explicitly permit the upstream RAM implementation. Database implementations
// must be supplied by the application through its own AccountStorage adapter.
impl AccountStorage for MemoryStore {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        let transaction = cssr::Storage::transaction(self).or(Err(Error::Storage))?;
        Ok(Transaction::new(Box::new(MemoryTransaction(transaction))))
    }
}
struct MemoryTransaction<'a>(Box<dyn cssr::Transaction + 'a>);
impl AtomicTransaction for MemoryTransaction<'_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.0.get(key).or(Err(Error::Storage))
    }
    fn current_range(
        &mut self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<CurrentRecord>, Error> {
        self.0
            .current_range(start, end, limit)
            .or(Err(Error::Storage))
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.0.put(key, value).or(Err(Error::Storage))
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.0.delete(key).or(Err(Error::Storage))
    }
    fn commit(self: Box<Self>) -> Result<(), Error> {
        self.0.commit().or(Err(Error::Storage))
    }
    fn commit_before(mut self: Box<Self>, deadline: &CommitDeadline<'_>) -> Result<(), Error> {
        // cssr's RAM transaction already owns its exclusive mutex. Commit swaps
        // staged records under that same guard without acquiring another lock.
        let (key, value) = deadline.commit_record()?;
        self.0.put(key, &value).or(Err(Error::Storage))?;
        self.0.commit().or(Err(Error::Storage))
    }
    fn rollback(self: Box<Self>) -> Result<(), Error> {
        self.0.rollback().or(Err(Error::Storage))
    }
}
/// Typed serialization facade over an application's atomic transaction.
pub struct Transaction<'a>(Box<dyn AtomicTransaction + 'a>);
impl<'a> Transaction<'a> {
    /// Wrap an application-owned transaction without opening a database.
    pub fn new(transaction: Box<dyn AtomicTransaction + 'a>) -> Self {
        Self(transaction)
    }
    pub fn get<T: DeserializeOwned>(&mut self, key: &[u8]) -> Result<Option<T>, Error> {
        self.0
            .get(key)?
            .map(|v| serde_json::from_slice(&v).or(Err(Error::Storage)))
            .transpose()
    }
    /// Decode a bounded current snapshot without leaving the host transaction.
    /// This is an issuer operation, never a member lookup or account-history API.
    pub fn current_range<T: DeserializeOwned>(
        &mut self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, T)>, Error> {
        self.0
            .current_range(start, end, limit)?
            .into_iter()
            .map(|(key, value)| {
                serde_json::from_slice(&value)
                    .map(|value| (key, value))
                    .or(Err(Error::Storage))
            })
            .collect()
    }
    pub fn put(&mut self, key: &[u8], value: &impl Serialize) -> Result<(), Error> {
        let bytes = serde_json::to_vec(value).or(Err(Error::Storage))?;
        self.0.put(key, &bytes)
    }
    pub fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.0.delete(key)
    }
    pub fn commit(self) -> Result<(), Error> {
        self.0.commit()
    }
    /// Refuse stale fresh authority after a late return too. A failure after
    /// successful commit does not undo state: reconcile by the original request
    /// identity, never manufacture a second accounting operation.
    pub fn commit_before(self, deadline: &CommitDeadline<'_>) -> Result<(), Error> {
        self.0.commit_before(deadline)?;
        deadline.check()?;
        Ok(())
    }
    pub fn rollback(self) -> Result<(), Error> {
        self.0.rollback()
    }
}
pub(crate) fn key(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![kind];
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    bytes
}

#[cfg(test)]
#[path = "../tests/internal/storage.rs"]
mod tests;
