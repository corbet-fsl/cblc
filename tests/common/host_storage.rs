//! Application-side SQL fixture; never part of the cblc library.
use cblc::{
    Error,
    accounting::AccountProofVerifier,
    accounting_ledger::{AccountLedger, AccountLedgerPolicy},
    admission::AdmissionTrust,
    storage::{AccountStorage, AtomicTransaction, CommitDeadline, Transaction},
};
use ed25519_dalek::SigningKey;
use std::path::Path;
struct HostStore(cssr::LibsqlStore);
struct HostTransaction<'a>(Box<dyn cssr::Transaction + 'a>);
impl AccountStorage for HostStore {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        Ok(Transaction::new(Box::new(HostTransaction(
            cssr::Storage::transaction(&mut self.0).map_err(|_| Error::Storage)?,
        ))))
    }
}
impl AtomicTransaction for HostTransaction<'_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.0.get(key).map_err(|_| Error::Storage)
    }
    fn current_range(
        &mut self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<cssr::CurrentRecord>, Error> {
        self.0
            .current_range(start, end, limit)
            .map_err(|_| Error::Storage)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.0.put(key, value).map_err(|_| Error::Storage)
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.0.delete(key).map_err(|_| Error::Storage)
    }
    fn commit(self: Box<Self>) -> Result<(), Error> {
        self.0.commit().map_err(|_| Error::Storage)
    }
    fn commit_before(mut self: Box<Self>, deadline: &CommitDeadline<'_>) -> Result<(), Error> {
        // All staged SQL work already holds the exclusive transaction. This is
        // the host's logical commit decision; durability may finish later.
        let (key, value) = deadline.commit_record()?;
        self.0.put(key, &value).map_err(|_| Error::Storage)?;
        self.0.commit().map_err(|_| Error::Storage)
    }
    fn rollback(self: Box<Self>) -> Result<(), Error> {
        self.0.rollback().map_err(|_| Error::Storage)
    }
}
pub fn open<V: AccountProofVerifier>(
    path: impl AsRef<Path>,
    trust: AdmissionTrust,
    policy: AccountLedgerPolicy,
    verifier: V,
    operator: SigningKey,
) -> Result<AccountLedger<V>, Error> {
    let store =
        HostStore(cssr::LibsqlStore::local(path, &trust.community_id).map_err(|_| Error::Storage)?);
    AccountLedger::with_store(store, trust, policy, verifier, operator)
}
