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
        consume(&mut transaction, &owner, &update, None),
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

#[test]
fn minimum_frontier_is_reached_only_in_the_actual_consumed_inbox_chain() {
    // This exercises the transactional inbox owner, not proof acceptance.
    // The caller's verified CAS must refuse and roll back an unreached frontier.
    let owner = [31; 32];
    for required in [[0; 32], [1; 32], [2; 32], [3; 32], [99; 32]] {
        let mut store = MemoryStore::default();
        let mut tx = AccountStorage::transaction(&mut store).unwrap();
        let mut previous = Inbox::default();
        for index in 1..=3 {
            let next = Inbox { root: [index; 32] };
            tx.put(
                &key(6, &[&owner, &next.root]),
                &PendingObligation {
                    previous,
                    commitment: [index; 32],
                },
            )
            .unwrap();
            previous = next;
        }
        tx.put(&key(5, &[&owner]), &previous).unwrap();
        tx.put(&key(10, &[&owner]), &3_u8).unwrap();
        tx.commit().unwrap();
        let update = ExtendedUpdate {
            previous_inbox: Inbox::default(),
            inbox: previous.clone(),
            effect: extensions::Effect::Update,
        };
        let mut tx = AccountStorage::transaction(&mut store).unwrap();
        let reached = consume(&mut tx, &owner, &update, Some(required)).unwrap();
        assert_eq!(reached, required != [99; 32]);
        if reached {
            tx.commit().unwrap();
        } else {
            tx.rollback().unwrap();
        }
        let mut tx = AccountStorage::transaction(&mut store).unwrap();
        let (_, pending) = read_obligations(&mut tx, owner).unwrap();
        assert_eq!(pending.len(), if reached { 0 } else { 3 });
        assert_eq!(
            extensions::applied(&mut tx, &owner).unwrap(),
            if reached { previous } else { Inbox::default() }
        );
        assert_eq!(
            tx.get::<u8>(&key(10, &[&owner])).unwrap(),
            if reached { None } else { Some(3) }
        );
    }
}
