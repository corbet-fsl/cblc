//! A proof dated in the NEXT rate window must not be accepted before that window
//! starts, or a member could spend next window's allowance now.
use super::*;
use cblc::storage::MemoryStore;

/// Accepts every proof: the question is the time check, not the circuit.
struct AcceptAll;
impl AccountProofVerifier for AcceptAll {
    fn scope(&self) -> AccountProofScope {
        AccountProofScope {
            circuit_digest: [1; 32],
            verifying_key_digest: [2; 32],
        }
    }
    fn verify(&self, _: &AccountStatement, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

/// Genesis request whose proof is dated `proof_time`; the server clock reads `server`.
fn dated(
    f: &Fixture,
    checkpoint_period: u64,
    proof_time: u64,
    server: u64,
) -> Result<AccountAcceptance, Error> {
    let mut configured = policy();
    configured.checkpoint_period_seconds = checkpoint_period;
    let mut ledger = AccountLedger::with_store(
        MemoryStore::default(),
        f.trust.clone(),
        configured.clone(),
        AcceptAll,
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    let root = fr(3);
    ledger
        .admit_checkpoint(proof_time / checkpoint_period, root)
        .ok();
    let community: [u8; 32] = Sha256::digest(f.trust.community_id.as_bytes()).into();
    let grant = f.grant_until(7, &f.device, 2000);
    let owner: [u8; 32] = B64
        .decode(grant.member_id.as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let account = configured.account.clone();
    let mut request = AccountRequest {
        statement: AccountStatement {
            protocol_version: 2,
            community,
            owner,
            policy_digest: account.digest(&community).unwrap(),
            enrollment_root: root,
            now: proof_time,
            valid_until: account.proof_valid_until(proof_time).unwrap(),
            genesis: true,
            previous_version: 0,
            next_version: 0,
            previous_state: [0; 32],
            next_state: fr(5),
            settlement_marker: [0; 32],
            policy: account.clone(),
        },
        request_id: [10; 32],
        proof_scope: AcceptAll.scope(),
        chat_public_key: B64.encode(&f.device.verifying_key().to_bytes()),
        issued_at: proof_time,
        expires_at: (proof_time + 50).min(account.proof_valid_until(proof_time).unwrap()),
        proof: vec![1],
        signature: String::new(),
    };
    sign(&mut request, &f.device);
    ledger.apply(
        &grant,
        &f.authorize_until(7, &f.device, 2000),
        super::current(&f.authorize_until(7, &f.device, 2000)),
        &request,
        || server,
    )
}

#[test]
fn control_a_proof_of_the_current_window_is_accepted() {
    let f = Fixture::new();
    assert!(dated(&f, 150, 940, 950).is_ok());
}

#[test]
fn a_proof_in_the_next_checkpoint_slot_is_refused() {
    let f = Fixture::new();
    // Rate window 1000 = checkpoint slot 1000: the next window is the next slot.
    assert_eq!(dated(&f, 1000, 1010, 950), Err(Error::Expired));
}

#[test]
fn a_proof_dated_in_the_next_rate_window_is_refused_even_when_the_slot_straddles_the_boundary() {
    let f = Fixture::new();
    // Slot 150 does not divide the window: slot [900,1050) holds the boundary at 1000, so
    // the same-slot rule alone lets 1010 through while the clock reads 950. The request's
    // issued_at must equal the proof time and the clock must not precede it.
    assert_eq!(dated(&f, 150, 1010, 950), Err(Error::Expired));
}

#[test]
fn a_proof_older_than_its_window_is_refused() {
    let f = Fixture::new();
    // Proof time in the previous window, server already in the next one.
    assert_eq!(dated(&f, 150, 960, 1010), Err(Error::Expired));
}
