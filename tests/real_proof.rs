//! Actual Noir/Barretenberg proofs through the process verifier and libSQL issuer.
mod common;
use cblc::{accounting::*, accounting_ledger::*, accounting_service::*};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    statement: AccountStatement,
    proof: String,
    proof_scope: AccountProofScope,
}
#[test]
fn real_account_proofs_round_trip_through_libsql() {
    let Ok(directory) = std::env::var("CBLC_PROOF_DIRECTORY") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let records: Vec<Record> =
        serde_json::from_slice(&std::fs::read(directory.join("records.json")).unwrap()).unwrap();
    assert_eq!(records.len(), 2);
    let f = common::Fixture::new();
    let config = ProcessVerifierConfig {
        node: std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("node"))
            .find(|p| p.is_absolute() && p.is_file())
            .unwrap(),
        script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("runtime/accounting/node-verifier.mjs"),
        artifact_config: directory.join("config.json"),
        scope: records[0].proof_scope.clone(),
        timeout: Duration::from_secs(60),
        maximum_parallel: 1,
        max_proof_bytes: 1024 * 1024,
        node_heap_megabytes: 2048,
    };
    let policy = AccountLedgerPolicy {
        account: records[0].statement.policy.clone(),
        max_authorization_seconds: 100,
        max_proof_bytes: 1024 * 1024,
        checkpoint_period_seconds: 1000,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let open = || {
        AccountLedger::open(
            &path,
            f.trust.clone(),
            policy.clone(),
            ProcessAccountVerifier::new(config.clone()).unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap()
    };
    let mut ledger = open();
    ledger
        .admit_checkpoint(0, records[0].statement.enrollment_root)
        .unwrap();
    let mut requests = Vec::new();
    for (index, record) in records.into_iter().enumerate() {
        let mut request = AccountRequest {
            issued_at: record.statement.now,
            expires_at: record.statement.now + 60,
            statement: record.statement,
            request_id: [10 + index as u8; 32],
            proof_scope: record.proof_scope,
            chat_public_key: B64.encode(&f.device.verifying_key().to_bytes()),
            proof: HEXLOWER.decode(record.proof.as_bytes()).unwrap(),
            signature: String::new(),
        };
        request.signature = B64.encode(
            &f.device
                .sign(&account_request_bytes(&request).unwrap())
                .to_bytes(),
        );
        let accepted = ledger
            .apply(
                &f.grant(7, &f.device),
                &f.authorize(7, &f.device),
                &request,
                || request.issued_at,
            )
            .unwrap();
        verify_account_acceptance(
            &accepted,
            &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        requests.push((request, accepted));
    }
    drop(ledger);
    let mut ledger = open();
    let (request, accepted) = requests.last().unwrap();
    assert_eq!(
        ledger
            .apply(
                &f.grant(7, &f.device),
                &f.authorize(7, &f.device),
                request,
                || 200
            )
            .unwrap(),
        *accepted
    );
}
