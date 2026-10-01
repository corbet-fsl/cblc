//! Imported overlong/cyclic storage must fail without accepting any proof.
use super::*;
use crate::storage::{AccountStorage, MemoryStore};

#[test]
fn corrupt_overlong_obligation_chain_is_bounded_and_rollback_preserves_entries() {
    let owner = [19; 32];
    let mut store = MemoryStore::default();
    let mut transaction = AccountStorage::transaction(&mut store).unwrap();
    let mut previous = Inbox::default();
    for index in 1..=65 {
        let next = Inbox { root: [index; 32] };
        transaction
            .put(
                &key(6, &[&owner, &next.root]),
                &PendingObligation {
                    previous,
                    commitment: [index; 32],
                },
            )
            .unwrap();
        previous = next;
    }
    transaction.put(&key(5, &[&owner]), &previous).unwrap();
    transaction.commit().unwrap();
    let update = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: previous,
        effect: extensions::Effect::Update,
    };
    let mut transaction = AccountStorage::transaction(&mut store).unwrap();
    assert_eq!(
        read_obligations(&mut transaction, owner),
        Err(Error::Capacity)
    );
    assert_eq!(
        consume(&mut transaction, &owner, &update),
        Err(Error::Capacity)
    );
    transaction.rollback().unwrap();
    let mut transaction = AccountStorage::transaction(&mut store).unwrap();
    assert!(
        transaction
            .get::<PendingObligation>(&key(6, &[&owner, &update.inbox.root]))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        read_obligations(&mut transaction, owner),
        Err(Error::Capacity)
    );
}
