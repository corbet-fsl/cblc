//! CI-only interactive issuer fixture. All inputs are public statements/proofs.
#[path = "../tests/common/mod.rs"]
mod common;
use cblc::{
    Error,
    accounting::*,
    accounting_ledger::*,
    accounting_service::{AccountService, AccountServiceRequest, AccountServiceResponse},
    extensions::*,
    pins::{PinSpendVerifier, SpentChange, change_binding},
    verification::{ExtensionLimits, ProcessExtensionVerifier},
};
use cpns::{
    Fingerprint,
    server::{Change, ChangeTokenVerifier, MemoryStore, Pin, Pins},
};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    io::{self, BufRead, Write},
    num::NonZeroUsize,
    path::PathBuf,
    time::Duration,
};

struct RejectLegacy;
impl AccountProofVerifier for RejectLegacy {
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
fn config(scope: AccountProofScope) -> cvfy::ProcessVerifierConfig {
    cvfy::ProcessVerifierConfig {
        node: std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("node"))
            .find(|p| p.is_absolute() && p.is_file())
            .unwrap(),
        script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("runtime/extensions/node-verifier.mjs"),
        artifact_config: PathBuf::from(std::env::args().nth(1).unwrap()),
        scope,
        timeout: Duration::from_secs(180),
        maximum_parallel: 1,
        max_proof_bytes: EXTENSION_PROOF_BYTES,
        node_heap_megabytes: 4096,
    }
}
fn main() {
    let fixture = common::Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let mut ledger: Option<AccountLedger<RejectLegacy>> = None;
    let mut tokens = std::collections::BTreeMap::new();
    let mut sequence = 0_u8;
    let mut policy = None;
    let mut scope = None;
    for line in io::stdin().lock().lines() {
        let v: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let result = (|| -> Result<Value, Error> {
            match v["op"].as_str().unwrap() {
                "init" => {
                    let proof_scope: AccountProofScope =
                        serde_json::from_value(v["scope"].clone()).unwrap();
                    let extension: ExtensionPolicy =
                        serde_json::from_value(v["extension"].clone()).unwrap();
                    let settings = AccountLedgerPolicy {
                        account: serde_json::from_value(v["policy"].clone()).unwrap(),
                        max_authorization_seconds: 100,
                        max_proof_bytes: EXTENSION_PROOF_BYTES,
                        checkpoint_period_seconds: 1000,
                    };
                    let verifier = ProcessExtensionVerifier::new(
                        config(proof_scope.clone()),
                        config(proof_scope.clone()),
                    )?;
                    let mut opened = AccountLedger::open(
                        directory.path().join("issuer.db"),
                        fixture.trust.clone(),
                        settings,
                        RejectLegacy,
                        SigningKey::from_bytes(&[9; 32]),
                    )?
                    .with_extensions(
                        extension.clone(),
                        verifier,
                        ExtensionLimits {
                            global_burst: 1000,
                            subject_burst: 500,
                            replenish: Duration::from_secs(1),
                            maximum_keys: NonZeroUsize::new(32).unwrap(),
                        },
                        ExtensionActivation {
                            account: serde_json::from_value(v["activation"]["account"].clone())
                                .unwrap(),
                            proof: HEXLOWER
                                .decode(v["activation"]["proof"].as_str().unwrap().as_bytes())
                                .unwrap(),
                        },
                    )?;
                    opened
                        .admit_checkpoint(0, serde_json::from_value(v["root"].clone()).unwrap())?;
                    ledger = Some(opened);
                    policy = Some(extension);
                    scope = Some(proof_scope);
                    Ok(json!(true))
                }
                "apply" => {
                    let update: ExtendedUpdate =
                        serde_json::from_value(v["update"].clone()).unwrap();
                    let statement: AccountStatement =
                        serde_json::from_value(v["statement"].clone()).unwrap();
                    let member = v["member"].as_u64().unwrap() as u8;
                    sequence = sequence.checked_add(1).unwrap();
                    let mut request = AccountRequest {
                        issued_at: statement.now,
                        expires_at: statement.valid_until,
                        statement,
                        request_id: [sequence; 32],
                        proof_scope: scope.clone().unwrap(),
                        chat_public_key: B64.encode(&fixture.device.verifying_key().to_bytes()),
                        proof: HEXLOWER
                            .decode(v["proof"].as_str().unwrap().as_bytes())
                            .unwrap(),
                        signature: String::new(),
                    };
                    request.signature = B64.encode(
                        &fixture
                            .device
                            .sign(&account_request_bytes(&request)?)
                            .to_bytes(),
                    );
                    let now = request.issued_at;
                    let mut service =
                        AccountService::new(ledger.take().unwrap(), || now, 16 * 1024 * 1024)?
                            .with_extension_issuer(
                                cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap(),
                            );
                    let operation = AccountServiceRequest::ApplyExtended {
                        grant: fixture.grant(member, &fixture.device),
                        authorization: fixture.authorize(member, &fixture.device),
                        request: Box::new(request.clone()),
                        update: update.clone(),
                    };
                    assert!(
                        service
                            .handle_for_member(&[member ^ 1; 48], operation.clone())
                            .is_err()
                    );
                    let response = service.handle_for_member(&[member; 48], operation);
                    ledger = Some(service.into_ledger());
                    let AccountServiceResponse::ApplyExtended {
                        acceptance: accepted,
                        certificate,
                    } = response?
                    else {
                        return Err(Error::InvalidInput);
                    };
                    if matches!(update.effect, Effect::Change { .. }) {
                        tokens.insert(
                            member,
                            SpentChange {
                                acceptance: accepted,
                                request,
                                update,
                            },
                        );
                    }
                    Ok(json!(certificate))
                }
                "deposit" => {
                    let batch: Vec<(Deposit, Vec<u8>)> = v["batch"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|e| {
                            (
                                serde_json::from_value(e["deposit"].clone()).unwrap(),
                                HEXLOWER
                                    .decode(e["proof"].as_str().unwrap().as_bytes())
                                    .unwrap(),
                            )
                        })
                        .collect();
                    ledger
                        .as_mut()
                        .unwrap()
                        .deposit_batch(&batch, || v["now"].as_u64().unwrap())?;
                    Ok(json!(true))
                }
                "inbox" => {
                    let now = v["now"].as_u64().unwrap();
                    let member = v["member"].as_u64().unwrap() as u8;
                    let mut request = AccountStatusRequest {
                        community: sha2::Sha256::digest(fixture.trust.community_id.as_bytes())
                            .into(),
                        owner: serde_json::from_value(v["owner"].clone()).unwrap(),
                        request_id: None,
                        challenge: [77; 32],
                        chat_public_key: B64.encode(&fixture.device.verifying_key().to_bytes()),
                        issued_at: now,
                        expires_at: now + 1,
                        signature: String::new(),
                    };
                    request.signature = B64.encode(
                        &fixture
                            .device
                            .sign(&cblc::obligations::request_bytes(&request)?)
                            .to_bytes(),
                    );
                    let grant = fixture.grant(member, &fixture.device);
                    let authority = fixture.authorize(member, &fixture.device);
                    let mut wrong_purpose = request.clone();
                    wrong_purpose.signature = B64.encode(
                        &fixture
                            .device
                            .sign(&account_status_bytes(&wrong_purpose)?)
                            .to_bytes(),
                    );
                    assert!(
                        ledger
                            .as_mut()
                            .unwrap()
                            .authenticated_obligations(&grant, &authority, &wrong_purpose, || now)
                            .is_err()
                    );
                    for field in 0..3 {
                        let mut cross_scope = request.clone();
                        match field {
                            0 => cross_scope.community[0] ^= 1,
                            1 => cross_scope.owner[0] ^= 1,
                            _ => cross_scope.expires_at = authority.expires_at + 1,
                        }
                        cross_scope.signature = B64.encode(
                            &fixture
                                .device
                                .sign(&cblc::obligations::request_bytes(&cross_scope)?)
                                .to_bytes(),
                        );
                        assert!(
                            ledger
                                .as_mut()
                                .unwrap()
                                .authenticated_obligations(&grant, &authority, &cross_scope, || now)
                                .is_err()
                        );
                    }
                    for (before, after) in [(now, now + 1), (now, now - 1), (0, now)] {
                        let tick = std::cell::Cell::new(before);
                        assert!(
                            ledger
                                .as_mut()
                                .unwrap()
                                .authenticated_obligations(&grant, &authority, &request, || {
                                    tick.replace(after)
                                })
                                .is_err()
                        );
                    }
                    let mut service =
                        AccountService::new(ledger.take().unwrap(), || now, 16 * 1024 * 1024)?;
                    let operation = AccountServiceRequest::Obligations {
                        grant,
                        authorization: authority,
                        request: request.clone(),
                    };
                    assert!(
                        service
                            .handle_for_member(&[member ^ 1; 48], operation.clone())
                            .is_err()
                    );
                    let response = service.handle_for_member(&[member; 48], operation);
                    ledger = Some(service.into_ledger());
                    let AccountServiceResponse::Obligations(response) = response? else {
                        return Err(Error::InvalidInput);
                    };
                    let key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
                    cblc::obligations::verify_response(&request, &response, &key, now)?;
                    assert!(
                        cblc::obligations::verify_response(&request, &response, &key, now + 1)
                            .is_err()
                    );
                    let mut replay = request.clone();
                    replay.challenge[0] ^= 1;
                    assert!(
                        cblc::obligations::verify_response(&replay, &response, &key, now).is_err()
                    );
                    let mut tampered = response.clone();
                    tampered.inbox.root[0] ^= 1;
                    assert!(
                        cblc::obligations::verify_response(&request, &tampered, &key, now).is_err()
                    );
                    for field in 0..3 {
                        let mut invalid = response.clone();
                        match field {
                            0 => invalid.observed_at = request.issued_at - 1,
                            1 => invalid.observed_at = now + 1,
                            _ => {
                                invalid.entries = vec![
                                    cblc::extensions::PendingObligation {
                                        previous: Default::default(),
                                        commitment: [1; 32],
                                    };
                                    65
                                ];
                            }
                        }
                        assert!(
                            cblc::obligations::verify_response(&request, &invalid, &key, now)
                                .is_err()
                        );
                    }
                    for field in 0..4 {
                        let mut invalid = request.clone();
                        match field {
                            0 => invalid.request_id = Some([1; 32]),
                            1 => invalid.chat_public_key = "invalid".into(),
                            2 => invalid.signature = "invalid".into(),
                            _ => invalid.challenge = [0; 32],
                        }
                        assert!(
                            cblc::obligations::verify_response(&invalid, &response, &key, now)
                                .is_err()
                        );
                    }
                    let foreign_key = SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes();
                    assert!(
                        cblc::obligations::verify_response(&request, &response, &foreign_key, now)
                            .is_err()
                    );
                    Ok(json!({"root":response.inbox,"entries":response.entries}))
                }
                "record" => {
                    let record: PublicRecord = serde_json::from_value(v["record"].clone()).unwrap();
                    let proof = HEXLOWER
                        .decode(v["proof"].as_str().unwrap().as_bytes())
                        .unwrap();
                    Ok(json!(ledger.as_mut().unwrap().check_record(
                        record.owner,
                        &record.context,
                        &record,
                        &proof,
                        || v["now"].as_u64().unwrap()
                    )?))
                }
                "binding" | "pins" => {
                    let member = v["member"].as_u64().unwrap() as u8;
                    let name = HEXLOWER.encode(&[member; 48]);
                    let change = Change {
                        community: "community.example",
                        member: &name,
                        field: "age",
                        expected: Pin {
                            fingerprint: Fingerprint::from_bytes([1; 32]),
                            revision: 1,
                        },
                        replacement: Fingerprint::from_bytes([2; 32]),
                    };
                    if v["op"] == "binding" {
                        return Ok(json!(change_binding(&change)?));
                    }
                    let verifier = PinSpendVerifier {
                        operator_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
                        scope: scope.clone().unwrap(),
                        policy: policy.clone().unwrap(),
                    };
                    let token = tokens.get(&member).unwrap();
                    futures::executor::block_on(async {
                        verifier.verify_spent(&change, token).await.unwrap();
                        let wrong = HEXLOWER.encode(&[member + 1; 48]);
                        assert!(
                            verifier
                                .verify_spent(
                                    &Change {
                                        member: &wrong,
                                        ..change
                                    },
                                    token
                                )
                                .await
                                .is_err()
                        );
                        assert!(
                            verifier
                                .verify_spent(
                                    &Change {
                                        field: "location",
                                        ..change
                                    },
                                    token
                                )
                                .await
                                .is_err()
                        );
                        for member in ["invalid", "aa", "AA"] {
                            assert!(
                                verifier
                                    .verify_spent(&Change { member, ..change }, token)
                                    .await
                                    .is_err()
                            );
                        }
                        assert!(
                            verifier
                                .verify_spent(
                                    &Change {
                                        community: "foreign",
                                        ..change
                                    },
                                    token
                                )
                                .await
                                .is_err()
                        );
                        assert!(
                            verifier
                                .verify_spent(
                                    &Change {
                                        replacement: change.expected.fingerprint,
                                        ..change
                                    },
                                    token
                                )
                                .await
                                .is_err()
                        );
                        for variant in 0..8 {
                            let mut damaged = SpentChange {
                                acceptance: token.acceptance.clone(),
                                request: token.request.clone(),
                                update: token.update.clone(),
                            };
                            match variant {
                                0 => damaged.request.proof_scope.circuit_digest[0] ^= 1,
                                1 => damaged.acceptance.statement.next_state[31] ^= 1,
                                2 => damaged.acceptance.request_id[0] ^= 1,
                                3 => damaged.acceptance.proof_scope.verifying_key_digest[0] ^= 1,
                                4 => damaged.acceptance.request_digest[0] ^= 1,
                                5 => damaged.acceptance.signature = "invalid".into(),
                                6 => damaged.update.inbox.root[0] ^= 1,
                                _ => damaged.update.effect = Effect::Update,
                            }
                            assert!(verifier.verify_spent(&change, &damaged).await.is_err());
                        }
                        let store = MemoryStore::new("community.example").unwrap();
                        let pins = Pins::new(store, verifier);
                        pins.pin(change.member, change.field, change.expected.fingerprint)
                            .await
                            .unwrap();
                        let changed = pins
                            .change(
                                change.member,
                                change.field,
                                change.expected,
                                change.replacement,
                                token,
                            )
                            .await
                            .unwrap();
                        assert_eq!(changed.revision, 2);
                        assert!(
                            pins.change(
                                change.member,
                                change.field,
                                change.expected,
                                change.replacement,
                                token
                            )
                            .await
                            .is_err()
                        );
                    });
                    Ok(json!(true))
                }
                _ => Err(Error::InvalidInput),
            }
        })();
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(e) => json!({"ok":false,"error":format!("{e:?}")}),
            }
        );
        io::stdout().flush().unwrap();
    }
}
