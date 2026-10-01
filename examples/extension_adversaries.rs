//! Public-proof fixture run explicitly after generation and under instrumentation.
#[path = "../tests/common/mod.rs"]
mod common;
#[path = "../tests/support/inspect.rs"]
#[allow(dead_code)]
mod inspection;
#[cfg(feature = "publication")]
#[path = "../tests/support/publication.rs"]
mod publication;
use cblc::{
    Error,
    accounting::*,
    accounting_ledger::*,
    extensions::*,
    verification::{ExtensionLimits, ProcessExtensionVerifier},
};
use common::{Fixture, proofs::RealVerifier};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use std::{
    cell::Cell,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::Duration,
};

fn limits() -> ExtensionLimits {
    ExtensionLimits {
        global_burst: 1000,
        subject_burst: 500,
        replenish: Duration::from_secs(1),
        maximum_keys: NonZeroUsize::new(32).unwrap(),
    }
}
fn verifier(scope: AccountProofScope, directory: &Path) -> ProcessExtensionVerifier {
    let config = cvfy::ProcessVerifierConfig {
        node: std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("node"))
            .find(|p| p.is_absolute() && p.is_file())
            .unwrap(),
        script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("runtime/extensions/node-verifier.mjs"),
        artifact_config: directory.join("config.json"),
        scope,
        timeout: Duration::from_secs(180),
        maximum_parallel: 1,
        max_proof_bytes: EXTENSION_PROOF_BYTES,
        node_heap_megabytes: 4096,
    };
    ProcessExtensionVerifier::new(config.clone(), config).unwrap()
}
fn activation(init: &Value) -> ExtensionActivation {
    ExtensionActivation {
        account: serde_json::from_value(init["activation"]["account"].clone()).unwrap(),
        proof: HEXLOWER
            .decode(init["activation"]["proof"].as_str().unwrap().as_bytes())
            .unwrap(),
    }
}
fn base(
    path: &Path,
    fixture: &Fixture,
    settings: AccountLedgerPolicy,
) -> AccountLedger<RealVerifier> {
    let ledger = AccountLedger::open(
        path,
        fixture.trust.clone(),
        settings,
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    #[cfg(feature = "publication")]
    let ledger = {
        let mut unactivated = ledger;
        assert_eq!(
            unactivated.public_verifier_material(
                1,
                1,
                &cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap()
            ),
            Err(Error::UnsupportedCapability)
        );
        unactivated
    };
    ledger
}
fn request(value: &Value, scope: &AccountProofScope, fixture: &Fixture, id: u8) -> AccountRequest {
    let statement: AccountStatement = serde_json::from_value(value["statement"].clone()).unwrap();
    let mut request = AccountRequest {
        issued_at: statement.now,
        expires_at: statement.valid_until,
        statement,
        request_id: [id; 32],
        proof_scope: scope.clone(),
        chat_public_key: B64.encode(&fixture.device.verifying_key().to_bytes()),
        proof: HEXLOWER
            .decode(value["proof"].as_str().unwrap().as_bytes())
            .unwrap(),
        signature: String::new(),
    };
    request.signature = B64.encode(
        &fixture
            .device
            .sign(&account_request_bytes(&request).unwrap())
            .to_bytes(),
    );
    request
}
fn replace(database: &inspection::Connection, key: &[u8], bytes: &[u8]) {
    database.execute_batch(&format!("INSERT OR REPLACE INTO cssr_records(community_id,key,value) VALUES('community.example',X'{}',X'{}')", HEXLOWER.encode(key), HEXLOWER.encode(bytes))).unwrap();
}
fn record_key(kind: u8, owner: &[u8; 32]) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&32_u64.to_be_bytes());
    bytes.extend_from_slice(owner);
    bytes
}
fn main() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".extension-test");
    let trace: Vec<Value> =
        serde_json::from_slice(&std::fs::read(directory.join("public-trace.json")).unwrap())
            .unwrap();
    let init = &trace
        .iter()
        .find(|v| v["request"]["op"] == "init" && v["response"]["ok"] == true)
        .unwrap()["request"];
    let scope: AccountProofScope = serde_json::from_value(init["scope"].clone()).unwrap();
    let extension: ExtensionPolicy = serde_json::from_value(init["extension"].clone()).unwrap();
    let settings = AccountLedgerPolicy {
        account: serde_json::from_value(init["policy"].clone()).unwrap(),
        max_authorization_seconds: 100,
        max_proof_bytes: EXTENSION_PROOF_BYTES,
        checkpoint_period_seconds: 1000,
    };
    let fixture = Fixture::new();
    for variant in 0..6 {
        let temporary = tempfile::tempdir().unwrap();
        let mut configured = settings.clone();
        let mut probe = activation(init);
        let mut configured_scope = scope.clone();
        match variant {
            0 => configured_scope = RealVerifier::default().scope(),
            1 => configured.max_proof_bytes = EXTENSION_PROOF_BYTES - 1,
            2 => probe.account.genesis = false,
            3 => probe.account.community[0] ^= 1,
            4 => probe.account.policy.initial_credit -= 1,
            _ => probe.proof.resize(EXTENSION_PROOF_BYTES + 1, 0),
        }
        let result = base(&temporary.path().join("refusal.db"), &fixture, configured)
            .with_extensions(
                extension.clone(),
                verifier(configured_scope, &directory),
                limits(),
                probe,
            );
        assert!(
            matches!(result, Err(error) if error == if variant == 0 { Error::PolicyMismatch } else { Error::InvalidInput })
        );
    }
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("active.db");
    let mut ledger = base(&path, &fixture, settings.clone())
        .with_extensions(
            extension.clone(),
            verifier(scope.clone(), &directory),
            limits(),
            activation(init),
        )
        .unwrap();
    ledger
        .admit_checkpoint(0, serde_json::from_value(init["root"].clone()).unwrap())
        .unwrap();
    #[cfg(feature = "publication")]
    let authenticated_material = {
        let material = publication::exercise(&mut ledger);
        let mut service =
            cblc::accounting_service::AccountService::new(ledger, || 110, 16 * 1024 * 1024)
                .unwrap();
        assert_eq!(
            service.public_verifier_material(1, 1),
            Err(Error::UnsupportedCapability)
        );
        service = service
            .with_extension_issuer(cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap());
        assert_eq!(
            service.public_verifier_material(1, 1).unwrap().community,
            fixture.trust.community_id
        );
        ledger = service.into_ledger();
        material
    };
    let database = inspection::Connection::open(&path).unwrap();
    let genesis: Vec<&Value> = trace
        .iter()
        .filter(|v| {
            v["request"]["op"] == "apply"
                && v["request"]["statement"]["genesis"] == true
                && v["response"]["ok"] == true
        })
        .take(4)
        .map(|v| &v["request"])
        .collect();
    assert_eq!(genesis.len(), 4);
    let first = request(genesis[0], &scope, &fixture, 7);
    let update: ExtendedUpdate = serde_json::from_value(genesis[0]["update"].clone()).unwrap();
    for variant in 0..3 {
        let mut changed = update.clone();
        match variant {
            0 => changed.previous_inbox.root = [1; 32],
            1 => changed.effect = Effect::Change { binding: [0; 32] },
            _ => changed.effect = Effect::Change { binding: [1; 32] },
        }
        assert_eq!(
            ledger.apply_extended(
                &fixture.grant(7, &fixture.device),
                &fixture.authorize(7, &fixture.device),
                &first,
                &changed,
                || first.issued_at
            ),
            Err(if variant == 0 {
                Error::Replay
            } else {
                Error::InvalidInput
            })
        );
    }
    let mut accepted = Vec::new();
    for value in genesis {
        let member = value["member"].as_u64().unwrap() as u8;
        let request = request(value, &scope, &fixture, member);
        let update = serde_json::from_value(value["update"].clone()).unwrap();
        accepted.push(
            ledger
                .apply_extended(
                    &fixture.grant(member, &fixture.device),
                    &fixture.authorize(member, &fixture.device),
                    &request,
                    &update,
                    || request.issued_at,
                )
                .unwrap(),
        );
    }
    let certificate = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    let next = &trace
        .iter()
        .find(|value| {
            value["request"]["op"] == "apply"
                && value["request"]["statement"]["genesis"] == false
                && value["response"]["ok"] == true
        })
        .unwrap()["request"];
    let member = next["member"].as_u64().unwrap() as u8;
    let candidate = request(next, &scope, &fixture, 77);
    assert_eq!(candidate.statement.settlement_marker, [0; 32]);
    let mut altered: ExtendedUpdate = serde_json::from_value(next["update"].clone()).unwrap();
    altered.effect = Effect::Change { binding: [1; 32] };
    assert_eq!(
        ledger.apply_extended(
            &fixture.grant(member, &fixture.device),
            &fixture.authorize(member, &fixture.device),
            &candidate,
            &altered,
            || candidate.issued_at
        ),
        Err(Error::InvalidInput)
    );
    for variant in 0..2 {
        let mut damaged = accepted[0].clone();
        if variant == 0 {
            damaged.statement.community[0] ^= 1;
            damaged.statement.policy_digest = damaged
                .statement
                .policy
                .digest(&damaged.statement.community)
                .unwrap();
        } else {
            damaged.proof_scope.circuit_digest[0] ^= 1;
        }
        // A valid operator signature is insufficient across the active ledger scope.
        damaged.signature = B64.encode(
            &SigningKey::from_bytes(&[9; 32])
                .sign(&account_acceptance_bytes(&damaged).unwrap())
                .to_bytes(),
        );
        assert!(matches!(
            ledger.certify_extended(&damaged, &certificate),
            Err(Error::PolicyMismatch)
        ));
    }
    let value = &trace
        .iter()
        .find(|v| v["request"]["op"] == "record" && v["response"]["ok"] == true)
        .unwrap()["request"];
    let record: PublicRecord = serde_json::from_value(value["record"].clone()).unwrap();
    let proof = HEXLOWER
        .decode(value["proof"].as_str().unwrap().as_bytes())
        .unwrap();
    let now = value["now"].as_u64().unwrap();
    #[cfg(feature = "publication")]
    publication::verify_record(&authenticated_material, &record, &proof);
    let mut read_request = AccountStatusRequest {
        community: record.community,
        owner: record.owner,
        request_id: None,
        challenge: [61; 32],
        chat_public_key: B64.encode(&fixture.device.verifying_key().to_bytes()),
        issued_at: now,
        expires_at: now + 90,
        signature: String::new(),
    };
    for variant in 0..5 {
        let mut request = read_request.clone();
        let mut grant = fixture.grant(7, &fixture.device);
        let mut authority = fixture.authorize(7, &fixture.device);
        match variant {
            0 => request.chat_public_key = B64.encode(&fixture.issuer.verifying_key().to_bytes()),
            1 => grant.expires_at = request.expires_at - 1,
            2 => authority.expires_at = request.expires_at - 1,
            3 => {
                request.issued_at = 1990;
                request.expires_at = 2050;
                grant.expires_at = 3000;
                authority.expires_at = 3000;
            }
            _ => request.issued_at += 1,
        }
        request.signature = B64.encode(
            &fixture
                .device
                .sign(&cblc::obligations::request_bytes(&request).unwrap())
                .to_bytes(),
        );
        grant.signature = B64.encode(
            &fixture
                .issuer
                .sign(&cblc::admission::admission_bytes(&grant).unwrap())
                .to_bytes(),
        );
        authority.signature = B64.encode(
            &SigningKey::from_bytes(&[7; 32])
                .sign(&cblc::admission::device_authorization_bytes(&authority).unwrap())
                .to_bytes(),
        );
        assert!(
            matches!(ledger.authenticated_obligations(&grant, &authority, &request, || now), Err(error) if error == if variant == 0 { Error::Admission } else { Error::Expired })
        );
    }
    assert_eq!(
        ledger.obligations(record.owner).unwrap(),
        (Inbox::default(), vec![])
    );
    let mut other = record.owner;
    other[0] ^= 1;
    assert_eq!(
        ledger.check_record(other, &record.context, &record, &proof, || now),
        Err(Error::Admission)
    );
    let mut context = record.context.clone();
    context.challenge[0] ^= 1;
    assert_eq!(
        ledger.check_record(record.owner, &context, &record, &proof, || now),
        Err(Error::Admission)
    );
    let calls = Cell::new(0);
    assert_eq!(
        ledger.check_record(record.owner, &record.context, &record, &proof, || {
            let call = calls.get();
            calls.set(call + 1);
            if call == 0 {
                now
            } else {
                record.context.expires_at
            }
        }),
        Err(Error::Expired)
    );
    let applied_key = record_key(7, &record.owner);
    replace(
        &database,
        &applied_key,
        &serde_json::to_vec(&Inbox { root: [1; 32] }).unwrap(),
    );
    assert_eq!(
        ledger.check_record(record.owner, &record.context, &record, &proof, || now),
        Err(Error::Replay)
    );
    replace(
        &database,
        &applied_key,
        &serde_json::to_vec(&Inbox::default()).unwrap(),
    );
    let value = &trace
        .iter()
        .find(|v| v["request"]["op"] == "deposit" && v["response"]["ok"] == true)
        .unwrap()["request"];
    let batch: Vec<(Deposit, Vec<u8>)> = value["batch"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                serde_json::from_value(entry["deposit"].clone()).unwrap(),
                HEXLOWER
                    .decode(entry["proof"].as_str().unwrap().as_bytes())
                    .unwrap(),
            )
        })
        .collect();
    replace(&database, &record_key(10, &batch[0].0.recipient), b"64");
    assert_eq!(
        ledger.deposit_batch(&batch, || value["now"].as_u64().unwrap()),
        Err(Error::Capacity)
    );
    replace(&database, b"extensions", b"[]");
    #[cfg(feature = "publication")]
    assert_eq!(
        ledger.public_verifier_material(1, 1, &certificate),
        Err(Error::UnsupportedCapability)
    );
    assert_eq!(
        ledger.check_record(record.owner, &record.context, &record, &proof, || now),
        Err(Error::UnsupportedCapability)
    );
    read_request.signature = B64.encode(
        &fixture
            .device
            .sign(&cblc::obligations::request_bytes(&read_request).unwrap())
            .to_bytes(),
    );
    assert!(matches!(
        ledger.authenticated_obligations(
            &fixture.grant(7, &fixture.device),
            &fixture.authorize(7, &fixture.device),
            &read_request,
            || now
        ),
        Err(Error::UnsupportedCapability)
    ));
    assert!(matches!(
        base(&path, &fixture, settings).with_extensions(
            extension,
            verifier(scope, &directory),
            limits(),
            activation(init)
        ),
        Err(Error::PolicyMismatch)
    ));
    println!(
        "Real extension activation, signed scope, frontier, expiry and capacity refusals passed"
    );
}
