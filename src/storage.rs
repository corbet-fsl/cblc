//! Caller-owned atomic accounting state. The library opens no databases.
use crate::Error;
pub use cssr::MemoryStore;
use serde::{Serialize, de::DeserializeOwned};
/// A store that supplies atomic issuer transactions.
pub trait AccountStorage: Send {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error>;
}
/// Atomic host transaction. Reads and writes share one serializable transaction.
/// Drop without commit must roll back. A successful commit durably and atomically
/// updates all keys; uncertain commit outcomes require exact idempotent retry.
/// The keys contain only selected accounting commitments and replay metadata,
/// never raw provider payloads, balances, counterparties or holder openings.
pub trait AtomicTransaction {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error>;
    fn delete(&mut self, key: &[u8]) -> Result<(), Error>;
    fn commit(self: Box<Self>) -> Result<(), Error>;
    fn rollback(self: Box<Self>) -> Result<(), Error>;
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
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.0.put(key, value).or(Err(Error::Storage))
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.0.delete(key).or(Err(Error::Storage))
    }
    fn commit(self: Box<Self>) -> Result<(), Error> {
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
