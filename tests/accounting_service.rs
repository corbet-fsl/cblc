//! Service boundary tests use actual maintained holder proofs and the shipped verifier.
mod common;
use cblc::{Error, accounting::*, accounting_ledger::*, accounting_service::*};
use common::{
    Fixture,
    proofs::{self, RealVerifier},
};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
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
    let ledger = AccountLedger::open(
        path,
        fixture.trust.clone(),
        policy(),
        verifier,
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    assert_eq!(ledger.community(), fixture.trust.community_id);
    ledger
}
fn genesis(fixture: &Fixture) -> AccountRequest {
    proofs::request(0, 10, fixture)
}

#[test]
fn member_wire_cannot_supply_time_or_admin_operations() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut service = AccountService::new(
        open(&dir.path().join("accounts"), &f, RealVerifier::default()),
        || 110,
        100_000,
    )
    .unwrap();
    assert_eq!(service.community(), f.trust.community_id);
    service
        .publish_verified_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    for body in [
        serde_json::json!({"action":"tuneWaitingPeriod","seconds":1000}),
        serde_json::json!({"action":"publishCheckpoint","root":proofs::record(0).statement.enrollment_root}),
        serde_json::json!({"action":"apply","grant":f.grant(7,&f.device),"authorization":f.authorize(7,&f.device),"request":genesis(&f),"now":110}),
    ] {
        assert_eq!(
            service.handle_json(&serde_json::to_vec(&body).unwrap()),
            Err(Error::InvalidInput)
        );
    }
    assert_eq!(service.handle_json(&vec![0; 100_001]), Err(Error::Capacity));
    let good = serde_json::json!({"action":"apply","grant":f.grant(7,&f.device),"authorization":f.authorize(7,&f.device),"request":genesis(&f)});
    assert!(good["grant"].get("issuerKeyId").is_some());
    let response = service
        .handle_json(&serde_json::to_vec(&good).unwrap())
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response).unwrap()["action"],
        "apply"
    );
    let (configured, tuning) = service.policy().unwrap();
    assert_eq!(configured, policy().account);
    assert_eq!(tuning.revision, 0);
    let original = genesis(&f);
    let mut request = AccountStatusRequest {
        community: original.statement.community,
        owner: original.statement.owner,
        request_id: None,
        challenge: [37; 32],
        chat_public_key: original.chat_public_key,
        issued_at: 110,
        expires_at: 170,
        signature: String::new(),
    };
    request.signature = data_encoding::BASE64URL_NOPAD.encode(
        &f.device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    let observed = service
        .handle_for_member(
            &[7; 48],
            AccountServiceRequest::Status {
                grant: f.grant(7, &f.device),
                authorization: f.authorize(7, &f.device),
                request: request.clone(),
            },
        )
        .unwrap();
    let AccountServiceResponse::Status(observed) = observed else {
        panic!("status response")
    };
    verify_account_status_response(
        &observed,
        &request,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(observed.acceptance.unwrap().request_id, original.request_id);
}

#[test]
fn server_clock_overrules_member_time_and_retry_recovers_after_tuning() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let clock = Arc::new(AtomicU64::new(181));
    let observed = clock.clone();
    let mut service = AccountService::new(
        open(&dir.path().join("accounts"), &f, RealVerifier::default()),
        move || observed.load(Ordering::SeqCst),
        100_000,
    )
    .unwrap();
    service
        .publish_verified_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let request = AccountServiceRequest::Apply {
        grant: f.grant(7, &f.device),
        authorization: f.authorize(7, &f.device),
        request: Box::new(genesis(&f)),
    };
    assert!(matches!(
        service.handle(request.clone()),
        Err(Error::Expired)
    ));
    clock.store(110, Ordering::SeqCst);
    let accepted = service.handle(request.clone()).unwrap();
    assert!(matches!(accepted, AccountServiceResponse::Apply(_)));
    let tune = service.tune_waiting_period(0, 1100).unwrap();
    assert_eq!(tune.seconds, 1100);
    assert!(matches!(
        service.tune_waiting_period(0, 1200),
        Err(Error::PolicyMismatch)
    ));
    clock.store(181, Ordering::SeqCst);
    let retry = service.handle(request).unwrap();
    assert_eq!(
        serde_json::to_value(accepted).unwrap(),
        serde_json::to_value(retry).unwrap()
    );
}

#[test]
fn invalid_authority_cannot_register_an_account() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut service = AccountService::new(
        open(&dir.path().join("accounts"), &f, RealVerifier::default()),
        || 110,
        100_000,
    )
    .unwrap();
    service
        .publish_verified_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let bad = AccountServiceRequest::Apply {
        grant: f.grant(8, &f.device),
        authorization: f.authorize(8, &f.device),
        request: Box::new(genesis(&f)),
    };
    assert!(matches!(service.handle(bad), Err(Error::Admission)));
    service
        .handle(AccountServiceRequest::Apply {
            grant: f.grant(7, &f.device),
            authorization: f.authorize(7, &f.device),
            request: Box::new(genesis(&f)),
        })
        .unwrap();
}

#[test]
fn actual_js_client_request_is_accepted_by_rust_and_js_checks_the_signed_rust_reply() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    fn javascript(mode: &str, input: serde_json::Value) -> Vec<u8> {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/holder/test/rust-client-interop.mjs");
        let mut child = Command::new("node")
            .arg(script)
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        output.stdout
    }
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let request = genesis(&f);
    let operator = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let body = javascript(
        "prepare",
        serde_json::json!({"operatorPublicKey":operator,"grant":f.grant(7,&f.device),
        "authorization":f.authorize(7,&f.device),"prepare":{"record":{"statement":request.statement,
        "proof":data_encoding::HEXLOWER.encode(&request.proof),"proofScope":request.proof_scope},
        "chatPublicKey":request.chat_public_key,"expiresAt":request.expires_at,"requestId":request.request_id}}),
    );
    let mut service = AccountService::new(
        open(&dir.path().join("accounts"), &f, RealVerifier::default()),
        || 110,
        100_000,
    )
    .unwrap();
    service
        .publish_verified_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    let response: serde_json::Value =
        serde_json::from_slice(&service.handle_json(&body).unwrap()).unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let verified = javascript(
        "verify",
        serde_json::json!({"acceptance":response["value"],"request":envelope["request"],"operatorPublicKey":operator}),
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified).unwrap()["ok"],
        true
    );
}

#[test]
fn verifier_kills_and_reaps_timeout_then_releases_capacity_and_rejects_large_stdout() {
    use std::{
        fs,
        time::{Duration, Instant},
    };
    let node = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|path| path.join("node"))
        .find(|path| path.is_absolute() && path.is_file())
        .expect("Node is required for the process-verifier integration test");
    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("worker.mjs");
    let config = directory.path().join("config.json");
    fs::write(&config, "{}").unwrap();
    fs::write(&script, "process.stdin.resume(); setInterval(()=>{},1000);").unwrap();
    let verifier = ProcessAccountVerifier::new(ProcessVerifierConfig {
        node,
        script: script.clone(),
        artifact_config: config,
        scope: proofs::record(0).proof_scope,
        timeout: Duration::from_millis(500),
        maximum_parallel: 1,
        max_proof_bytes: 1024 * 1024,
        node_heap_megabytes: 64,
    })
    .unwrap();
    let statement = genesis(&Fixture::new()).statement;
    let started = Instant::now();
    assert_eq!(
        verifier.verify(&statement, &[1, 2, 3]),
        Err(Error::CryptoProvider)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    fs::write(
        &script,
        "process.stdin.resume(); process.stdout.write('x'.repeat(5000));",
    )
    .unwrap();
    assert_eq!(
        verifier.verify(&statement, &[1, 2, 3]),
        Err(Error::CryptoProvider)
    );
    // A well-formed refusal tests framing after cleanup; this worker never accepts a proof.
    let verdict = serde_json::json!({"verified":false,"proofScope":proofs::record(0).proof_scope})
        .to_string();
    fs::write(
        &script,
        format!(
            "process.stdin.resume(); process.stdout.write({});",
            serde_json::to_string(&verdict).unwrap()
        ),
    )
    .unwrap();
    assert_eq!(
        verifier.verify(&statement, &[1, 2, 3]),
        Err(Error::CryptoProvider)
    );
    assert_eq!(
        verifier.verify(&statement, &vec![0; 1024 * 1024 + 1]),
        Err(Error::InvalidInput)
    );
}

#[test]
fn service_capacity_rejects_invalid_bounds_and_preserves_host_policy() {
    let f = Fixture::new();
    for limit in [0, 16 * 1024 * 1024 + 1, 1, 16 * 1024 * 1024] {
        let dir = tempfile::tempdir().unwrap();
        let ledger = open(&dir.path().join("accounts"), &f, RealVerifier::default());
        let result = AccountService::new(ledger, || 120, limit);
        if limit == 0 || limit > 16 * 1024 * 1024 {
            assert!(matches!(result, Err(Error::InvalidInput)));
        } else {
            let service = result.unwrap();
            assert_eq!(service.max_request_bytes(), limit);
            assert_eq!(service.into_ledger().account_policy(), &policy().account);
        }
    }
}
