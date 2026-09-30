//! Small storage boundary for the facade; libSQL runs exclusively through cssr/crlt.
use crate::Error;
pub use cssr::{LibsqlStore, MemoryStore};
use serde::{Serialize, de::DeserializeOwned};
/// A store that supplies atomic issuer transactions.
pub trait AccountStorage: Send {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error>;
}
impl<T: cssr::Storage> AccountStorage for T {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        Ok(Transaction(self.transaction().map_err(|_| Error::Storage)?))
    }
}
pub struct Transaction<'a>(Box<dyn cssr::Transaction + 'a>);
impl Transaction<'_> {
    pub fn get<T: DeserializeOwned>(&mut self, key: &[u8]) -> Result<Option<T>, Error> {
        self.0
            .get(key)
            .map_err(|_| Error::Storage)?
            .map(|v| serde_json::from_slice(&v).map_err(|_| Error::Storage))
            .transpose()
    }
    pub fn put(&mut self, key: &[u8], value: &impl Serialize) -> Result<(), Error> {
        let bytes = serde_json::to_vec(value).map_err(|_| Error::Storage)?;
        self.0.put(key, &bytes).map_err(|_| Error::Storage)
    }
    pub fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.0.delete(key).map_err(|_| Error::Storage)
    }
    pub fn commit(self) -> Result<(), Error> {
        self.0.commit().map_err(|_| Error::Storage)
    }
    pub fn rollback(self) -> Result<(), Error> {
        self.0.rollback().map_err(|_| Error::Storage)
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
