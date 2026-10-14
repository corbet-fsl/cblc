//! Voucher roles and the bond-addressed mailbox at the ledger.
use super::*;
use cblc::storage::MemoryStore;

/// These tests never verify a proof: roles and the mailbox are plain ledger records.
struct NoProofs;
impl AccountProofVerifier for NoProofs {
    fn scope(&self) -> AccountProofScope {
        AccountProofScope {
            circuit_digest: [11; 32],
            verifying_key_digest: [12; 32],
        }
    }
    fn verify(&self, _: &AccountStatement, _: &[u8]) -> Result<(), Error> {
        Err(Error::UnsupportedCapability)
    }
}

fn ledger() -> AccountLedger<NoProofs> {
    let fixture = Fixture::new();
    AccountLedger::with_store(
        MemoryStore::default(),
        fixture.trust.clone(),
        policy(),
        NoProofs,
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
}

#[test]
fn roles_default_to_member_and_reject_unknown_classes() {
    let mut ledger = ledger();
    let owner = [4; 32];
    assert_eq!(ledger.role(&owner).unwrap(), 0);
    ledger.set_role(&owner, 2).unwrap();
    assert_eq!(ledger.role(&owner).unwrap(), 2);
    assert!(matches!(
        ledger.set_role(&owner, 3),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        ledger.set_role(&[0; 32], 1),
        Err(Error::InvalidInput)
    ));
    ledger.set_role(&owner, 0).unwrap();
    assert_eq!(ledger.role(&owner).unwrap(), 0);
}

#[test]
fn a_tag_posts_exactly_once_for_all_time() {
    let mut ledger = ledger();
    let tag = [7; 32];
    assert!(!ledger.obligation_waiting(&tag).unwrap());
    ledger.post_obligation(&tag).unwrap();
    assert!(ledger.obligation_waiting(&tag).unwrap());
    assert!(matches!(ledger.post_obligation(&tag), Err(Error::Replay)));
    assert!(matches!(
        ledger.post_obligation(&[0; 32]),
        Err(Error::InvalidInput)
    ));
}

#[test]
fn posted_tags_and_unconsumed_mailbox_rows_age_out_after_the_retention() {
    let mut ledger = ledger();
    assert_eq!(ledger.obligation_retention_days(), 90);
    for bad in [0, 6, 731] {
        assert!(matches!(
            ledger.set_obligation_retention_days(bad),
            Err(Error::InvalidInput)
        ));
    }
    ledger.set_obligation_retention_days(30).unwrap();
    let day = 86_400;
    let (old, young) = ([7; 32], [8; 32]);
    ledger.post_obligation_at(&old, 10 * day).unwrap();
    // Inside the retention the tag is still waiting and cannot be posted again.
    ledger.post_obligation_at(&young, 39 * day).unwrap();
    assert!(ledger.obligation_waiting(&old).unwrap());
    assert!(matches!(
        ledger.post_obligation_at(&old, 39 * day),
        Err(Error::Replay)
    ));
    // Past the retention the next post drops the aged rows, including the mailbox row.
    ledger.post_obligation_at(&[9; 32], 41 * day).unwrap();
    assert!(!ledger.obligation_waiting(&old).unwrap());
    assert!(ledger.obligation_waiting(&young).unwrap());
    // A re-post is harmless garbage again (the sponsor never consumes it twice).
    ledger.post_obligation_at(&old, 41 * day).unwrap();
}
