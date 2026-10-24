//! Actual Noir/Barretenberg proofs through the process verifier and libSQL issuer.
mod common;
use cblc::{accounting::*, accounting_ledger::*, accounting_service::*};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use std::path::PathBuf;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    statement: AccountStatement,
    proof: String,
    proof_scope: AccountProofScope,
}
#[test]
fn real_account_proofs_round_trip_through_libsql() {
    let directory =
        std::env::var("CBLC_PROOF_DIRECTORY").expect("CI must generate real holder proofs");
    let directory = PathBuf::from(directory);
    let records: Vec<Record> =
        serde_json::from_slice(&std::fs::read(directory.join("records.json")).unwrap()).unwrap();
    assert_eq!(records.len(), 2);
    let f = common::Fixture::new();
    let artifacts = common::native::account(&directory);
    assert_eq!(artifacts.scope(), records[0].proof_scope);
    let policy = AccountLedgerPolicy {
        account: records[0].statement.policy.clone(),
        max_authorization_seconds: 100,
        max_proof_bytes: 1024 * 1024,
        checkpoint_period_seconds: 1000,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let open = || {
        common::host_storage::open(
            &path,
            f.trust.clone(),
            policy.clone(),
            NativeAccountVerifier::new(common::native::options(1024 * 1024), artifacts.clone())
                .unwrap(),
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
                crate::current(&f.authorize(7, &f.device)),
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
                crate::current(&f.authorize(7, &f.device)),
                request,
                || 200
            )
            .unwrap(),
        *accepted
    );
}

/// Test registry: every device is current. Tests that need a removed device implement their own.
pub(crate) struct AllCurrent;
impl cblc::current_device::CurrentLineage for AllCurrent {
    fn is_current(&self, _: &[u8; 32]) -> bool {
        true
    }
}
pub(crate) fn current(
    authorization: &cblc::admission::DeviceAuthorization,
) -> cblc::current_device::CurrentDevice {
    cblc::current_device::CurrentDevice::attest(&AllCurrent, authorization).unwrap()
}
