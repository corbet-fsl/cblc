use super::*;
#[test]
fn memory_transactions_commit_rollback_drop_and_delete_atomically() {
    let mut store = MemoryStore::default();
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), None);
    tx.put(b"state", &7u64).unwrap();
    tx.commit().unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(b"state", &9u64).unwrap();
    tx.rollback().unwrap();
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), Some(7));
    tx.delete(b"state").unwrap();
    drop(tx);
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), Some(7));
    tx.delete(b"state").unwrap();
    tx.commit().unwrap();
    let mut tx = store.transaction().unwrap();
    assert_eq!(tx.get::<u64>(b"state").unwrap(), None);
    // Serialization errors are sanitized and do not commit partial metadata.
    let invalid = std::collections::BTreeMap::from([(vec![1u8], 1)]);
    assert!(matches!(tx.put(b"bad", &invalid), Err(Error::Storage)));
    tx.put(b"state", &"wrong type").unwrap();
    assert!(matches!(tx.get::<u64>(b"state"), Err(Error::Storage)));
}
#[test]
fn poisoned_upstream_memory_is_refused() {
    let store = MemoryStore::default();
    let mut other = store.clone();
    let _ = std::thread::spawn(move || {
        let _tx = other.transaction().unwrap();
        panic!("test poison");
    })
    .join();
    let mut store = store;
    assert!(matches!(store.transaction(), Err(Error::Storage)));
}
// Upstream transaction errors are an integration boundary, not own logic.
struct Unavailable;
impl cssr::Transaction for Unavailable {
    fn get(&mut self, _: &[u8]) -> cssr::Result<Option<Vec<u8>>> {
        Err(cssr::Error)
    }
    fn put(&mut self, _: &[u8], _: &[u8]) -> cssr::Result<()> {
        Err(cssr::Error)
    }
    fn delete(&mut self, _: &[u8]) -> cssr::Result<()> {
        Err(cssr::Error)
    }
    fn commit(self: Box<Self>) -> cssr::Result<()> {
        Err(cssr::Error)
    }
    fn rollback(self: Box<Self>) -> cssr::Result<()> {
        Err(cssr::Error)
    }
}
#[test]
fn upstream_failures_cannot_become_success_or_expose_details() {
    let mut tx = Transaction::new(Box::new(MemoryTransaction(Box::new(Unavailable))));
    assert!(matches!(tx.get::<u64>(b"key"), Err(Error::Storage)));
    assert!(matches!(tx.put(b"key", &1), Err(Error::Storage)));
    assert!(matches!(tx.delete(b"key"), Err(Error::Storage)));
    assert!(matches!(tx.commit(), Err(Error::Storage)));
    let tx = Transaction::new(Box::new(MemoryTransaction(Box::new(Unavailable))));
    assert!(matches!(tx.rollback(), Err(Error::Storage)));
}
