//! Real maintained proofs, signed authority and libSQL storage adversaries.

#[path = "accounting_ledger/bounds.rs"]
mod bounds;
mod common;
#[path = "accounting_ledger/integrity.rs"]
mod integrity;
#[path = "accounting_ledger/wire.rs"]
mod wire;
use cblc::{Error, accounting::*, accounting_ledger::*};
use common::{
    Fixture,
    proofs::{self, RealVerifier},
};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};
#[path = "support/inspect.rs"]
mod inspection;
use inspection::Connection;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    time::Duration,
};

struct BlockedVerifier {
    inner: RealVerifier,
    entered: Sender<()>,
    release: Receiver<()>,
}

impl AccountProofVerifier for BlockedVerifier {
    fn scope(&self) -> AccountProofScope {
        self.inner.scope()
    }
    fn verify(&self, statement: &AccountStatement, proof: &[u8]) -> Result<(), Error> {
        self.inner.verify(statement, proof)?;
        self.entered.send(()).map_err(|_| Error::CryptoProvider)?;
        self.release
            .recv_timeout(Duration::from_secs(180))
            .map_err(|_| Error::CryptoProvider)
    }
}

fn blocked_verifier() -> (BlockedVerifier, Receiver<()>, Sender<()>) {
    let (entered, observed) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    (
        BlockedVerifier {
            inner: RealVerifier::default(),
            entered,
            release: resume,
        },
        observed,
        release,
    )
}

fn fr(n: u8) -> [u8; 32] {
    let mut value = [0; 32];
    value[31] = n;
    value
}
fn policy() -> AccountLedgerPolicy {
    // Test values only. Library consumers must choose their own complete policy.
    AccountLedgerPolicy {
        account: AccountPolicy {
            initial_credit: 3,
            maximum_available: 4,
            outgoing_reservation: 1,
            incoming_reservation: 1,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 2000,
            newcomer_period: 100,
            rate_window: 1000,
            newcomer_admissions: 2,
            maximum_admissions: 4,
            refill_period: 100,
            refill_units: 1,
            abandon_after: 1000,
        },
        max_authorization_seconds: 100,
        max_proof_bytes: 1024 * 1024,
        checkpoint_period_seconds: 1000,
    }
}
fn open<V: AccountProofVerifier>(path: &Path, fixture: &Fixture, verifier: V) -> AccountLedger<V> {
    AccountLedger::open(
        path,
        fixture.trust.clone(),
        policy(),
        verifier,
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
}
fn sign(request: &mut AccountRequest, key: &SigningKey) {
    request.signature = B64.encode(
        &key.sign(&account_request_bytes(request).unwrap())
            .to_bytes(),
    );
}

fn genesis(fixture: &Fixture) -> AccountRequest {
    proofs::request(0, 10, fixture)
}

fn successor(prior: &AccountRequest, fixture: &Fixture, id: u8) -> AccountRequest {
    let request = proofs::request(1, id, fixture);
    assert_eq!(prior.statement.next_version, 0);

    request
}

#[test]
fn rejected_proof_cannot_register_and_genesis_is_lifetime_unique_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let request = genesis(&f);
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let mut corrupt = request.clone();
    corrupt.proof[0] ^= 1;
    sign(&mut corrupt, &f.device);
    assert_eq!(
        ledger.apply(&g, &a, &corrupt, || 120),
        Err(Error::CryptoProvider)
    );
    drop(ledger);
    let mut ledger = open(&path, &f, RealVerifier::default());
    let accepted = ledger.apply(&g, &a, &request, || 120).unwrap();
    verify_account_acceptance(
        &accepted,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    drop(ledger);
    let mut ledger = open(&path, &f, RealVerifier::default());
    let mut second = request.clone();
    second.request_id = [11; 32];
    sign(&mut second, &f.device);
    assert_eq!(ledger.apply(&g, &a, &second, || 130), Err(Error::Replay));
    assert_eq!(ledger.apply(&g, &a, &request, || 200).unwrap(), accepted);
}

#[test]
fn exact_retry_does_not_verify_or_debit_again_and_changed_bytes_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let v = RealVerifier::default();
    let calls = v.calls.clone();
    let mut ledger = open(&dir.path().join("ledger.sqlite"), &f, v);
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let request = genesis(&f);
    let first = ledger.apply(&g, &a, &request, || 120).unwrap();
    assert_eq!(ledger.apply(&g, &a, &request, || 200).unwrap(), first);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let mut changed = request.clone();
    changed.proof.push(4);
    sign(&mut changed, &f.device);
    assert_eq!(ledger.apply(&g, &a, &changed, || 201), Err(Error::Replay));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn real_authority_and_common_checkpoint_are_required_before_verifying() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let v = RealVerifier::default();
    let calls = v.calls.clone();
    let mut ledger = open(&dir.path().join("ledger.sqlite"), &f, v);
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let request = genesis(&f);
    assert_eq!(
        ledger.apply(&g, &a, &request, || 120),
        Err(Error::Admission)
    );
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    assert_eq!(
        ledger.admit_checkpoint(0, fr(9)),
        Err(Error::PolicyMismatch)
    );
    let mut forged = request.clone();
    forged.signature = B64.encode(&[0; 64]);
    assert_eq!(ledger.apply(&g, &a, &forged, || 120), Err(Error::Signature));
    let wrong_root = f.authorize(8, &f.device);
    assert_eq!(
        ledger.apply(&g, &wrong_root, &request, || 120),
        Err(Error::Admission)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    ledger.apply(&g, &a, &request, || 120).unwrap();
    let mut unsigned_scope = request.clone();
    unsigned_scope.statement.enrollment_root = fr(9);
    assert_eq!(
        ledger.apply(&g, &a, &unsigned_scope, || 120),
        Err(Error::Signature)
    );
}

#[test]
fn expiry_and_clock_changes_during_verification_have_no_effect() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut ledger = open(
        &dir.path().join("ledger.sqlite"),
        &f,
        RealVerifier::default(),
    );
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let request = genesis(&f);
    for times in [[120, 120, 180], [120, 119, 120], [120, 120, 119]] {
        let index = Cell::new(0);
        let clock = || {
            let i = index.get();
            index.set(i + 1);
            times[i]
        };
        assert!(matches!(
            ledger.apply(&g, &a, &request, clock),
            Err(Error::Expired | Error::ClockRollback)
        ));
    }
    ledger.apply(&g, &a, &request, || 130).unwrap();
    assert_eq!(
        ledger.apply(&g, &a, &request, || 129),
        Err(Error::ClockRollback)
    );
}

#[test]
fn blocked_proof_allows_another_owner_to_commit_and_rechecks_shared_clock_floor() {
    for other_time in [120, 121] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let f = Fixture::new();
        let (verifier, entered, release) = blocked_verifier();
        let mut slow = open(&path, &f, verifier);
        slow.admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
            .unwrap();
        let g = f.grant(7, &f.device);
        let a = f.authorize(7, &f.device);
        let first = genesis(&f);
        let other_grant = f.grant(8, &f.device);
        let other_authorization = f.authorize(8, &f.device);
        let other = proofs::request(2, 21, &f);
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || slow.apply(&g, &a, &first, || 120));
            entered.recv_timeout(Duration::from_secs(180)).unwrap();
            // Open/configuration and checkpoint publication must also remain
            // possible while the first verifier is deliberately blocked.
            let mut fast = open(&path, &f, RealVerifier::default());
            fast.admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
                .unwrap();
            let accepted = fast.apply(&other_grant, &other_authorization, &other, || other_time);
            release.send(()).unwrap();
            let resumed = worker.join().unwrap();
            assert!(
                accepted.is_ok(),
                "another owner's commit must precede verifier release"
            );
            if other_time == 120 {
                assert!(resumed.is_ok());
            } else {
                assert_eq!(resumed, Err(Error::ClockRollback));
            }
        });
        let db = inspect(&path);
        assert_eq!(
            db.query_row("SELECT count(*) FROM frontiers", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            if other_time == 120 { 2 } else { 1 }
        );
    }
}

#[test]
fn successor_losing_during_verification_cannot_commit_its_state_or_response() {
    for same_request_id in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let f = Fixture::new();
        let mut fast = open(&path, &f, RealVerifier::default());
        fast.admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
            .unwrap();
        let g = f.grant(7, &f.device);
        let a = f.authorize(7, &f.device);
        let first = genesis(&f);
        fast.apply(&g, &a, &first, || 120).unwrap();
        let losing = successor(&first, &f, 11);
        let winning = proofs::request(3, if same_request_id { 11 } else { 12 }, &f);
        let (verifier, entered, release) = blocked_verifier();
        let mut slow = open(&path, &f, verifier);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| slow.apply(&g, &a, &losing, || 130));
            entered.recv_timeout(Duration::from_secs(180)).unwrap();
            let accepted = fast.apply(&g, &a, &winning, || 130);
            release.send(()).unwrap();
            let resumed = worker.join().unwrap();
            assert!(accepted.is_ok());
            assert_eq!(resumed, Err(Error::Replay));
        });
        let db = inspect(&path);
        let (state, request): (Vec<u8>, Vec<u8>) = db
            .query_row("SELECT state,latest_request FROM frontiers", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(state, winning.statement.next_state);
        assert_eq!(request, winning.request_id);
        // Both real competing operations reserve; neither settles an event.
        assert_eq!(winning.statement.settlement_marker, [0; 32]);
        assert_eq!(
            db.query_row("SELECT count(*) FROM markers", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM latest_acceptances", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn concurrently_cached_request_bypasses_original_expiry_but_requires_live_authority() {
    for completed in [200, 900, 1000] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let f = Fixture::new();
        let mut fast = open(&path, &f, RealVerifier::default());
        fast.admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
            .unwrap();
        let g = f.grant(7, &f.device);
        let a = f.authorize(7, &f.device);
        let first = genesis(&f);
        fast.apply(&g, &a, &first, || 120).unwrap();
        let reservation = successor(&first, &f, 11);
        fast.apply(&g, &a, &reservation, || 121).unwrap();
        let request = proofs::request(5, 12, &f);
        assert_ne!(request.statement.settlement_marker, [0; 32]);
        let (verifier, entered, release) = blocked_verifier();
        let mut slow = open(&path, &f, verifier);
        let now = AtomicU64::new(130);
        std::thread::scope(|scope| {
            let worker =
                scope.spawn(|| slow.apply(&g, &a, &request, || now.load(Ordering::SeqCst)));
            entered.recv_timeout(Duration::from_secs(180)).unwrap();
            let accepted = fast.apply(&g, &a, &request, || 130);
            now.store(completed, Ordering::SeqCst);
            release.send(()).unwrap();
            let resumed = worker.join().unwrap();
            let accepted = accepted.unwrap();
            if completed == 200 {
                assert_eq!(resumed.unwrap(), accepted);
            } else {
                assert_eq!(resumed, Err(Error::Expired));
            }
        });
        let db = inspect(&path);
        assert_eq!(
            db.query_row("SELECT count(*) FROM latest_acceptances", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM markers", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn checkpoint_slot_expiry_during_verification_cannot_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let mut configured = policy();
    configured.checkpoint_period_seconds = 150;
    let mut ledger = AccountLedger::open(
        &path,
        f.trust.clone(),
        configured,
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let times = [120, 120, 150];
    let index = Cell::new(0);
    let result = ledger.apply(
        &f.grant(7, &f.device),
        &f.authorize(7, &f.device),
        &genesis(&f),
        || {
            let i = index.get();
            index.set(i + 1);
            times[i]
        },
    );
    assert_eq!(result, Err(Error::Expired));
    let db = inspect(&path);
    assert_eq!(
        db.query_row("SELECT count(*) FROM frontiers", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT clock_floor FROM configuration", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

#[test]
fn root_authorized_devices_share_one_compare_and_swap_frontier() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let verifier = RealVerifier::default();
    let calls = verifier.calls.clone();
    let mut ledger = open(&path, &f, verifier);
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let first = genesis(&f);
    ledger.apply(&g, &a, &first, || 120).unwrap();
    let second = successor(&first, &f, 11);
    ledger.apply(&g, &a, &second, || 121).unwrap();
    let device = SigningKey::from_bytes(&[55; 32]);
    let mut competing = successor(&first, &f, 12);
    competing.chat_public_key = B64.encode(&device.verifying_key().to_bytes());
    sign(&mut competing, &device);
    assert_eq!(
        ledger.apply(
            &f.grant(7, &device),
            &f.authorize(7, &device),
            &competing,
            || 122
        ),
        Err(Error::Replay)
    );
    let cancellation = proofs::request(5, 13, &f);
    ledger.apply(&g, &a, &cancellation, || 133).unwrap();
    assert_ne!(cancellation.statement.settlement_marker, [0; 32]);
    let mut duplicate_event = cancellation.clone();
    duplicate_event.request_id = [14; 32];
    duplicate_event.statement.previous_version = cancellation.statement.next_version;
    duplicate_event.statement.next_version += 1;
    duplicate_event.statement.previous_state = cancellation.statement.next_state;
    sign(&mut duplicate_event, &f.device);
    let verified = calls.load(Ordering::SeqCst);
    assert_eq!(
        ledger.apply(&g, &a, &duplicate_event, || 134),
        Err(Error::Replay)
    );
    assert_eq!(calls.load(Ordering::SeqCst), verified);
    let db = inspect(&path);
    assert_eq!(
        db.query_row("SELECT count(*) FROM markers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn failure_after_marker_insertion_rolls_back_marker_state_response_and_clock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let first = genesis(&f);
    ledger.apply(&g, &a, &first, || 120).unwrap();
    let reservation = successor(&first, &f, 11);
    ledger.apply(&g, &a, &reservation, || 121).unwrap();
    let db = inspect(&path);
    db.execute_batch(
        "CREATE TRIGGER injected_failure BEFORE UPDATE ON cssr_records WHEN substr(NEW.key,1,1)=x'01'
        BEGIN SELECT RAISE(ABORT,'storage-test failure'); END;",
    )
    .unwrap();
    let second = proofs::request(5, 12, &f);
    assert_ne!(second.statement.settlement_marker, [0; 32]);
    assert_eq!(ledger.apply(&g, &a, &second, || 130), Err(Error::Storage));
    assert_eq!(
        db.query_row("SELECT count(*) FROM markers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT version FROM frontiers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM latest_acceptances", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT clock_floor FROM configuration", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        121
    );
    db.execute_batch("DROP TRIGGER injected_failure").unwrap();
    ledger.apply(&g, &a, &second, || 130).unwrap();
}

#[test]
fn recovered_device_status_is_challenge_bound_and_returns_no_new_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut ledger = open(
        &dir.path().join("ledger.sqlite"),
        &f,
        RealVerifier::default(),
    );
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let first = genesis(&f);
    let accepted = ledger
        .apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            || 120,
        )
        .unwrap();
    let device = SigningKey::from_bytes(&[55; 32]);
    let mut request = AccountStatusRequest {
        community: first.statement.community,
        owner: first.statement.owner,
        request_id: None,
        challenge: [22; 32],
        chat_public_key: B64.encode(&device.verifying_key().to_bytes()),
        issued_at: 200,
        expires_at: 250,
        signature: String::new(),
    };
    request.signature = B64.encode(
        &device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    let response = ledger
        .status(
            &f.grant(7, &device),
            &f.authorize(7, &device),
            &request,
            || 210,
        )
        .unwrap();
    let operator = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    verify_account_status_response(&response, &request, &operator).unwrap();
    assert_eq!(response.acceptance, Some(accepted));
    request.challenge = [23; 32];
    request.signature = B64.encode(
        &device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    assert_eq!(
        verify_account_status_response(&response, &request, &operator),
        Err(Error::Replay)
    );
    let mut forged = response.clone();
    forged.acceptance = None;
    assert_eq!(
        verify_account_status_response(&forged, &request, &operator),
        Err(Error::Replay)
    );
}

#[test]
fn canonical_fields_versions_unknown_wire_fields_and_policy_scope_fail_closed() {
    let f = Fixture::new();
    let first = genesis(&f);
    let mut bad = first.clone();
    bad.statement.next_state = [255; 32];
    assert_eq!(account_request_bytes(&bad), Err(Error::InvalidInput));
    let mut bad = first.clone();
    bad.statement.next_version = 1;
    assert_eq!(account_request_bytes(&bad), Err(Error::InvalidInput));
    let mut bad = first.clone();
    bad.statement.policy.incoming_reservation = 2;
    assert_eq!(account_request_bytes(&bad), Err(Error::InvalidInput));
    let mut json = serde_json::to_value(first).unwrap();
    json["statement"]["peer"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<AccountRequest>(json).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    drop(open(&path, &f, RealVerifier::default()));
    let mut changed = policy();
    changed.account.initial_credit = 2;
    assert!(matches!(
        AccountLedger::open(
            &path,
            f.trust,
            changed,
            RealVerifier::default(),
            SigningKey::from_bytes(&[9; 32])
        ),
        Err(Error::PolicyMismatch)
    ));
}

#[test]
#[ignore = "child process entry point; invoked only by independent_processes_race"]
fn ledger_process_worker() {
    let path = std::env::var("CFRM_ACCOUNT_TEST_DATABASE").unwrap();
    let id: u8 = std::env::var("CFRM_ACCOUNT_TEST_REQUEST")
        .unwrap()
        .parse()
        .unwrap();
    let gate = std::env::var("CFRM_ACCOUNT_TEST_GATE").unwrap();
    let f = Fixture::new();
    let mut ledger = open(Path::new(&path), &f, RealVerifier::default());
    let until = std::time::Instant::now() + std::time::Duration::from_secs(180);
    while !Path::new(&gate).exists() {
        assert!(std::time::Instant::now() < until);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let request = successor(&genesis(&f), &f, id);
    let result = ledger.apply(
        &f.grant(7, &f.device),
        &f.authorize(7, &f.device),
        &request,
        || 130,
    );
    assert!(result.is_ok() || result == Err(Error::Replay));
}

#[test]
fn independent_processes_race_and_reopen_returns_the_committed_winner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let gate = dir.path().join("go");
    let f = Fixture::new();
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    ledger
        .apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &genesis(&f),
            || 120,
        )
        .unwrap();
    drop(ledger);
    let mut children = Vec::new();
    for id in [11, 12] {
        children.push(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "ledger_process_worker", "--ignored"])
                .env("CFRM_ACCOUNT_TEST_DATABASE", &path)
                .env("CFRM_ACCOUNT_TEST_REQUEST", id.to_string())
                .env("CFRM_ACCOUNT_TEST_GATE", &gate)
                .spawn()
                .unwrap(),
        );
    }
    std::fs::write(&gate, b"go").unwrap();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let db = inspect(&path);
    assert_eq!(
        db.query_row("SELECT count(*) FROM latest_acceptances", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT version FROM frontiers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    let winner: Vec<u8> = db
        .query_row(
            "SELECT latest_request FROM frontiers WHERE owner=?1",
            [genesis(&f).statement.owner.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    let mut ledger = open(&path, &f, RealVerifier::default());
    let request = successor(&genesis(&f), &f, winner[0]);
    assert_eq!(
        ledger
            .apply(
                &f.grant(7, &f.device),
                &f.authorize(7, &f.device),
                &request,
                || 200
            )
            .unwrap()
            .request_id
            .as_slice(),
        winner
    );
}

#[path = "accounting_ledger/tuning.rs"]
mod tuning;

fn inspect(path: &Path) -> Connection {
    Connection::open(path).unwrap()
}

#[test]
fn pseudonym_survives_root_rotation_and_cannot_reopen_or_replay_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("continuity.sqlite");
    let f = Fixture::new();
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let g = f.grant(7, &f.device);
    let old = f.authorize(7, &f.device);
    let first = genesis(&f);
    let accepted = ledger.apply(&g, &old, &first, || 120).unwrap();
    let root = SigningKey::from_bytes(&[7; 32]);
    let new = SigningKey::from_bytes(&[99; 32]);
    let mut auth = old.clone();
    auth.root_public_key = B64.encode(&new.verifying_key().to_bytes());
    auth.signature = B64.encode(
        &new.sign(&cblc::admission::device_authorization_bytes(&auth).unwrap())
            .to_bytes(),
    );
    assert_eq!(
        ledger.apply(&g, &auth, &first, || 120),
        Err(Error::Admission)
    );
    let mut rotation = RootRotation {
        community: first.statement.community,
        owner: first.statement.owner,
        expected_revision: 0,
        expected_version: 0,
        expected_state: first.statement.next_state,
        old_root: old.root_public_key.clone(),
        new_root: auth.root_public_key.clone(),
        old_signature: String::new(),
        new_signature: String::new(),
    };
    let bytes = root_rotation_bytes(&rotation).unwrap();
    rotation.old_signature = B64.encode(&root.sign(&bytes).to_bytes());
    rotation.new_signature = B64.encode(&new.sign(&bytes).to_bytes());
    let mut forged = rotation.clone();
    forged.old_signature = forged.new_signature.clone();
    assert_eq!(ledger.rotate_root(&forged), Err(Error::Signature));
    ledger.rotate_root(&rotation).unwrap();
    assert_eq!(ledger.rotate_root(&rotation), Err(Error::Replay));
    drop(ledger);
    let mut ledger = open(&path, &f, RealVerifier::default());
    assert_eq!(
        ledger.apply(&g, &old, &first, || 120),
        Err(Error::Admission)
    );
    assert_eq!(ledger.apply(&g, &auth, &first, || 120).unwrap(), accepted);
    let mut reopen = first.clone();
    reopen.request_id = [99; 32];
    sign(&mut reopen, &f.device);
    assert_eq!(ledger.apply(&g, &auth, &reopen, || 120), Err(Error::Replay));
    let next = successor(&first, &f, 13);
    assert!(ledger.apply(&g, &auth, &next, || 130).is_ok());
}

#[test]
fn extension_activation_requires_a_real_proof() {
    let f = Fixture::new();
    let mut settings = policy();
    settings.max_proof_bytes = cblc::extensions::EXTENSION_PROOF_BYTES;
    let activation = cblc::extensions::ExtensionActivation {
        account: genesis(&f).statement,
        proof: vec![],
    };
    let ledger = AccountLedger::with_store(
        cblc::storage::MemoryStore::default(),
        f.trust,
        settings,
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    let config = cvfy::ProcessVerifierConfig {
        node: "/unavailable/node".into(),
        script: "/unavailable/verifier.mjs".into(),
        artifact_config: "/unavailable/config.json".into(),
        scope: AccountProofScope {
            circuit_digest: [71; 32],
            verifying_key_digest: [72; 32],
        },
        timeout: Duration::from_secs(1),
        maximum_parallel: 1,
        max_proof_bytes: cblc::extensions::EXTENSION_PROOF_BYTES,
        node_heap_megabytes: 64,
    };
    let verifier =
        cblc::verification::ProcessExtensionVerifier::new(config.clone(), config).unwrap();
    let result = ledger.with_extensions(
        cblc::extensions::ExtensionPolicy {
            revision: 1,
            public_record_quorum: 5,
            change_token_cost: 1,
            deposit_delay_seconds: 10,
            minimum_deposit_batch: 2,
        },
        verifier,
        cblc::verification::ExtensionLimits {
            global_burst: 10,
            subject_burst: 2,
            replenish: Duration::from_secs(180),
            maximum_keys: std::num::NonZeroUsize::new(16).unwrap(),
        },
        activation,
    );
    assert!(matches!(result, Err(Error::InvalidInput)));
}

#[test]
fn admission_rejects_legacy_root_ids_and_mismatched_pseudonyms() {
    let f = Fixture::new();
    let valid = f.grant(7, &f.device);
    cblc::admission::verify_admission(&valid, &f.trust, 120).unwrap();
    let mut old = valid.clone();
    old.version = 1;
    assert_eq!(
        cblc::admission::admission_bytes(&old),
        Err(Error::Admission)
    );
    let mut rerooted = valid.clone();
    let root = SigningKey::from_bytes(&[99; 32]);
    rerooted.member_id = B64.encode(&Sha256::digest(
        serde_json::to_vec(&serde_json::json!([
            "cmsg.member.v1",
            "community.example",
            B64.encode(&root.verifying_key().to_bytes())
        ]))
        .unwrap(),
    ));
    assert_eq!(
        cblc::admission::admission_bytes(&rerooted),
        Err(Error::Admission)
    );
    let mut altered = valid;
    altered.pseudonym = data_encoding::HEXLOWER.encode(&[8; 48]);
    assert_eq!(
        cblc::admission::admission_bytes(&altered),
        Err(Error::Admission)
    );
}
