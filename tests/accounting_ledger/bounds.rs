//! Host bounds and absent-account recovery use the shipped store and verifier.
use super::*;
use cblc::storage::MemoryStore;

fn memory(
    fixture: &Fixture,
    policy: AccountLedgerPolicy,
) -> Result<AccountLedger<RealVerifier>, Error> {
    AccountLedger::with_store(
        MemoryStore::default(),
        fixture.trust.clone(),
        policy,
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
}

#[test]
fn invalid_host_bounds_fail_before_state_creation() {
    let f = Fixture::new();
    for limit in [0, czkp::MAX_INTEGER + 1] {
        let mut configured = policy();
        configured.max_authorization_seconds = limit;
        assert!(matches!(memory(&f, configured), Err(Error::InvalidInput)));
        let mut configured = policy();
        configured.checkpoint_period_seconds = limit;
        assert!(matches!(memory(&f, configured), Err(Error::InvalidInput)));
    }
    for limit in [0, i32::MAX as usize + 1] {
        let mut configured = policy();
        configured.max_proof_bytes = limit;
        assert!(matches!(memory(&f, configured), Err(Error::InvalidInput)));
    }
    let mut f = f;
    f.trust.community_id.clear();
    assert!(matches!(memory(&f, policy()), Err(Error::InvalidInput)));
}

#[test]
fn malformed_scope_cannot_activate_a_real_verifier() {
    struct Misconfigured(RealVerifier, AccountProofScope);
    impl AccountProofVerifier for Misconfigured {
        fn scope(&self) -> AccountProofScope {
            self.1.clone()
        }
        fn verify(&self, statement: &AccountStatement, proof: &[u8]) -> Result<(), Error> {
            self.0.verify(statement, proof)
        }
    }
    let f = Fixture::new();
    for field in 0..2 {
        let mut scope = RealVerifier::default().scope();
        if field == 0 {
            scope.circuit_digest = [0; 32];
        } else {
            scope.verifying_key_digest = [0; 32];
        }
        assert!(matches!(
            AccountLedger::with_store(
                MemoryStore::default(),
                f.trust.clone(),
                policy(),
                Misconfigured(RealVerifier::default(), scope),
                SigningKey::from_bytes(&[9; 32]),
            ),
            Err(Error::InvalidInput)
        ));
    }
}

#[test]
fn policy_cannot_be_tuned_before_its_validity_start() {
    let f = Fixture::new();
    let mut configured = policy();
    configured.account.policy_valid_from = 10;
    let mut ledger = memory(&f, configured).unwrap();
    assert_eq!(
        ledger.update_waiting_period(0, 1100, || 9),
        Err(Error::Expired)
    );
}

#[test]
fn common_checkpoint_bounds_and_idempotent_publication() {
    let f = Fixture::new();
    let mut ledger = memory(&f, policy()).unwrap();
    assert_eq!(
        ledger.admit_checkpoint(0, [0; 32]),
        Err(Error::InvalidInput)
    );
    for slot in [u64::MAX, u64::MAX / 1000, czkp::MAX_INTEGER / 1000] {
        assert_eq!(
            ledger.admit_checkpoint(slot, fr(1)),
            Err(Error::InvalidInput)
        );
    }
    ledger.admit_checkpoint(0, fr(1)).unwrap();
    ledger.admit_checkpoint(0, fr(1)).unwrap();
    assert_eq!(
        ledger.admit_checkpoint(0, fr(2)),
        Err(Error::PolicyMismatch)
    );
    let mut configured = policy();
    configured.checkpoint_period_seconds = czkp::MAX_INTEGER;
    let mut boundary = memory(&f, configured).unwrap();
    boundary.admit_checkpoint(0, fr(1)).unwrap();
    assert_eq!(
        boundary.admit_checkpoint(1, fr(1)),
        Err(Error::InvalidInput)
    );
}

#[test]
fn signed_absent_account_status_does_not_register_or_mint_credit() {
    let f = Fixture::new();
    let mut ledger = memory(&f, policy()).unwrap();
    let mut request = AccountStatusRequest {
        community: Sha256::digest(f.trust.community_id.as_bytes()).into(),
        owner: Sha256::digest([7; 48]).into(),
        request_id: None,
        challenge: [22; 32],
        chat_public_key: B64.encode(&f.device.verifying_key().to_bytes()),
        issued_at: 110,
        expires_at: 170,
        signature: String::new(),
    };
    for request_id in [None, Some([11; 32])] {
        request.request_id = request_id;
        request.signature = B64.encode(
            &f.device
                .sign(&account_status_bytes(&request).unwrap())
                .to_bytes(),
        );
        let response = ledger
            .status(
                &f.grant(7, &f.device),
                &f.authorize(7, &f.device),
                &request,
                || 120,
            )
            .unwrap();
        verify_account_status_response(
            &response,
            &request,
            &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        assert!(response.acceptance.is_none());
    }
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let accepted = ledger
        .apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &genesis(&f),
            || 120,
        )
        .unwrap();
    assert_eq!(accepted.statement.next_version, 0);
}

#[test]
fn valid_signed_policy_change_is_refused_before_the_real_verifier_runs() {
    let f = Fixture::new();
    let verifier = RealVerifier::default();
    let calls = verifier.calls.clone();
    let mut ledger = AccountLedger::with_store(
        MemoryStore::default(),
        f.trust.clone(),
        policy(),
        verifier,
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    let original = genesis(&f);
    ledger
        .admit_checkpoint(0, original.statement.enrollment_root)
        .unwrap();
    let mut changed = original.clone();
    changed.statement.policy.initial_credit = 2;
    changed.statement.policy_digest = changed
        .statement
        .policy
        .digest(&changed.statement.community)
        .unwrap();
    sign(&mut changed, &f.device);
    assert_eq!(
        ledger.apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &changed,
            || 120
        ),
        Err(Error::PolicyMismatch)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    ledger
        .apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &original,
            || 120,
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
