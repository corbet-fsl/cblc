//! CI-only issuer of the native member world (tests/native-member-world.mts): a real
//! ledger and account service for ONE configurable community and time. All inputs are
//! public statements and proofs; every key is a fictional fixed test seed.
//!
//! Seeds (public test provenance, never trust): Policy key 1, ledger operator 9,
//! certificate issuer (P-256) 3, device `deviceSeed` (init). Fixture member number `n`
//! selects that member's root key `[n; 32]` and record recipient key `[n; 32]`, exactly
//! as in examples/extension_issuer.rs; its pseudonym is given separately.
#[path = "../tests/common/mod.rs"]
#[allow(dead_code)]
mod common;
#[path = "../tests/support/pin_spend.rs"]
mod pin_spend;
#[path = "../tests/holder/record-epoch-issuer.rs"]
#[allow(dead_code)]
mod records;
use cblc::{
    Error,
    accounting::*,
    accounting_ledger::{
        record_epoch::{RecipientRequest, recipient_bytes},
        *,
    },
    accounting_service::{AccountService, AccountServiceRequest, AccountServiceResponse},
    admission::{
        AdmissionGrant, AdmissionTrust, DeviceAuthorization, admission_bytes,
        device_authorization_bytes, policy_key_id,
    },
    extensions::*,
    pins::{PinSpendVerifier, SpentChange, change_binding},
    settlement::{
        SettlementConfig, SettlementPassRequest, SettlementSubmission, deposit_digest,
        settlement_pass_request_bytes,
    },
    verification::{ExtensionLimits, NativeExtensionVerifier},
};
use cpns::{
    Fingerprint,
    server::{Change, ChangeTokenVerifier, Pin},
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

/// The world's fixture authority: one Policy key ring active from `issued_at`, one device.
struct World {
    community: String,
    signer: csgn::Signer,
    device: SigningKey,
    issued_at: u64,
    fixture: common::Fixture,
}

const POLICY_SEED: u8 = 1;
const OPERATOR_SEED: u8 = 9;
const CERTIFICATE_SEED: u8 = 3;
/// Policy key lifetime from its activation; long enough for every grant of the world.
const POLICY_VALIDITY: u64 = 30 * 86_400;
/// The daily-settlement incarnation of this world's ledger (token proofs name it).
const INCARNATION: &str = "native-member-world";

impl World {
    fn new(community: &str, now: u64, device_seed: u8) -> Self {
        // Grants and device authorizations start shortly before the world's time.
        let issued_at = now.checked_sub(100).unwrap();
        let signer = csgn::Signer::new(
            community,
            csgn::SecretKey::from_seed(&mut [POLICY_SEED; 32]),
            issued_at,
            POLICY_VALIDITY,
        )
        .unwrap();
        let trust = AdmissionTrust {
            community_id: community.into(),
            policy_digest: common::encoded(3),
            policy_keys: signer.key_ring().clone(),
        };
        let device = SigningKey::from_bytes(&[device_seed; 32]);
        Self {
            community: community.into(),
            signer,
            fixture: common::Fixture {
                issuer: SigningKey::from_bytes(&[POLICY_SEED; 32]),
                device: device.clone(),
                trust,
            },
            device,
            issued_at,
        }
    }
    fn trust(&self) -> AdmissionTrust {
        self.fixture.trust.clone()
    }
    fn member_id(pseudonym: &[u8; 48]) -> String {
        B64.encode(&sha2::Sha256::digest(pseudonym))
    }
    fn grant(&mut self, pseudonym: &[u8; 48], expires_at: u64) -> AdmissionGrant {
        let mut grant = AdmissionGrant {
            version: 3,
            issuer_key_id: policy_key_id(
                &SigningKey::from_bytes(&[POLICY_SEED; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            community_id: self.community.clone(),
            member_id: Self::member_id(pseudonym),
            pseudonym: HEXLOWER.encode(pseudonym),
            chat_public_key: B64.encode(&self.device.verifying_key().to_bytes()),
            policy_digest: self.fixture.trust.policy_digest.clone(),
            policy_epoch: 1,
            passport_policy_digest: common::encoded(10),
            issued_at: self.issued_at,
            expires_at,
            signature: String::new(),
        };
        grant.signature = B64.encode(
            &self
                .signer
                .sign(
                    csgn::Kind::Credential,
                    &admission_bytes(&grant).unwrap(),
                    self.issued_at,
                    expires_at,
                )
                .unwrap(),
        );
        grant
    }
    fn authorize(&self, pseudonym: &[u8; 48], member: u8, expires_at: u64) -> DeviceAuthorization {
        let root = SigningKey::from_bytes(&[member; 32]);
        let mut authorization = DeviceAuthorization {
            version: 1,
            community_id: self.community.clone(),
            member_id: Self::member_id(pseudonym),
            root_public_key: B64.encode(&root.verifying_key().to_bytes()),
            device_public_key: B64.encode(&self.device.verifying_key().to_bytes()),
            issued_at: self.issued_at,
            expires_at,
            signature: String::new(),
        };
        authorization.signature = B64.encode(
            &root
                .sign(&device_authorization_bytes(&authorization).unwrap())
                .to_bytes(),
        );
        authorization
    }
}

fn pseudonym(v: &Value) -> [u8; 48] {
    HEXLOWER
        .decode(v["pseudonym"].as_str().unwrap().as_bytes())
        .unwrap()
        .try_into()
        .unwrap()
}
fn member(v: &Value) -> u8 {
    u8::try_from(v["member"].as_u64().unwrap()).unwrap()
}
fn hex32(v: &Value) -> [u8; 32] {
    HEXLOWER
        .decode(v.as_str().unwrap().as_bytes())
        .unwrap()
        .try_into()
        .unwrap()
}

struct PinChange {
    community: String,
    member: String,
    field: String,
    expected: Pin,
    replacement: Fingerprint,
}
impl PinChange {
    fn from(v: &Value) -> Self {
        Self {
            community: v["community"].as_str().unwrap().into(),
            member: v["member"].as_str().unwrap().into(),
            field: v["field"].as_str().unwrap().into(),
            expected: Pin {
                fingerprint: Fingerprint::from_bytes(hex32(&v["expected"]["fingerprint"])),
                revision: v["expected"]["revision"].as_u64().unwrap(),
            },
            replacement: Fingerprint::from_bytes(hex32(&v["replacement"])),
        }
    }
    fn change(&self) -> Change<'_> {
        Change {
            community: &self.community,
            member: &self.member,
            field: &self.field,
            expected: self.expected,
            replacement: self.replacement,
        }
    }
}

fn main() {
    let directory = tempfile::tempdir().unwrap();
    let mut world: Option<World> = None;
    let mut ledger: Option<AccountLedger<RejectLegacy>> = None;
    let mut spent: Option<SpentChange> = None;
    let mut sequence = 0_u8;
    let mut opened_stores = 0_u32;
    let mut extension_policy = None;
    let mut scope = None;
    let mut records = records::Records::default();
    let mut settlement: Option<cmbl::settlement::Epoch> = None;
    for line in io::stdin().lock().lines() {
        let v: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let result = (|| -> Result<Value, Error> {
            match v["op"].as_str().unwrap() {
                "init" => {
                    // Every start-up opens a store of its own: a refused attempt leaves nothing behind.
                    opened_stores += 1;
                    let now = v["now"].as_u64().unwrap();
                    let community = v["community"].as_str().unwrap();
                    let device = u8::try_from(v["deviceSeed"].as_u64().unwrap()).unwrap();
                    let created = World::new(community, now, device);
                    let proof_scope: AccountProofScope =
                        serde_json::from_value(v["scope"].clone()).unwrap();
                    let extension: ExtensionPolicy =
                        serde_json::from_value(v["extension"].clone()).unwrap();
                    let settings = AccountLedgerPolicy {
                        account: serde_json::from_value(v["policy"].clone()).unwrap(),
                        max_authorization_seconds: v["maxAuthorizationSeconds"].as_u64().unwrap(),
                        max_proof_bytes: EXTENSION_PROOF_BYTES,
                        checkpoint_period_seconds: v["checkpointPeriodSeconds"].as_u64().unwrap(),
                    };
                    // The exact ledger policy, for consumers that install the same ledger.
                    let ledger_policy = serde_json::to_value(&settings).unwrap();
                    let artifacts = common::native::extension_config(&PathBuf::from(
                        v["artifacts"].as_str().unwrap(),
                    ))?;
                    if artifacts.scope() != proof_scope {
                        return Err(Error::PolicyMismatch);
                    }
                    let options = common::native::options(1024 * 1024);
                    let verifier =
                        NativeExtensionVerifier::new(options.clone(), options, artifacts)?;
                    let mut opened = common::host_storage::open(
                        directory.path().join(format!("issuer-{opened_stores}.db")),
                        created.trust(),
                        settings,
                        RejectLegacy,
                        SigningKey::from_bytes(&[OPERATOR_SEED; 32]),
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
                    // The trusted host admits the world's enrollment root for its slot.
                    opened.admit_checkpoint(
                        v["slot"].as_u64().unwrap(),
                        serde_json::from_value(v["root"].clone()).unwrap(),
                    )?;
                    // As in extension_issuer: one open certificate period from the first
                    // second (holders name it {publicKey, validFrom: 1}).
                    opened.record_certificate_issuer(
                        common::CERTIFICATE_IDENTITY,
                        cssr::certificate::CertificateIssuer::new(&[CERTIFICATE_SEED; 32])
                            .unwrap()
                            .public_key(),
                        1,
                    )?;
                    ledger = Some(opened);
                    extension_policy = Some(extension);
                    scope = Some(proof_scope);
                    world = Some(created);
                    Ok(json!({
                        "operatorPublicKey": SigningKey::from_bytes(&[OPERATOR_SEED; 32]).verifying_key().to_bytes(),
                        "devicePublicKey": world.as_ref().unwrap().device.verifying_key().to_bytes(),
                        "policyKeyId": policy_key_id(&SigningKey::from_bytes(&[POLICY_SEED; 32]).verifying_key().to_bytes()),
                        "ledgerPolicy": ledger_policy,
                    }))
                }
                "apply" => {
                    let world = world.as_mut().unwrap();
                    let update: ExtendedUpdate =
                        serde_json::from_value(v["update"].clone()).unwrap();
                    let statement: AccountStatement =
                        serde_json::from_value(v["statement"].clone()).unwrap();
                    let pseudonym = pseudonym(&v);
                    let member = member(&v);
                    sequence = sequence.checked_add(1).unwrap();
                    let mut request = AccountRequest {
                        issued_at: statement.now,
                        expires_at: statement.valid_until,
                        statement,
                        request_id: [sequence; 32],
                        proof_scope: scope.clone().unwrap(),
                        chat_public_key: B64.encode(&world.device.verifying_key().to_bytes()),
                        proof: HEXLOWER
                            .decode(v["proof"].as_str().unwrap().as_bytes())
                            .unwrap(),
                        signature: String::new(),
                    };
                    request.signature = B64.encode(
                        &world
                            .device
                            .sign(&account_request_bytes(&request)?)
                            .to_bytes(),
                    );
                    let now = request.issued_at;
                    let until = request.expires_at + 1000;
                    let grant = world.grant(&pseudonym, until);
                    let authorization = world.authorize(&pseudonym, member, until);
                    let mut service =
                        AccountService::new(ledger.take().unwrap(), || now, 16 * 1024 * 1024)?
                            .with_extension_issuer(
                                cssr::certificate::CertificateIssuer::new(&[CERTIFICATE_SEED; 32])
                                    .unwrap(),
                                common::CERTIFICATE_IDENTITY,
                            )?;
                    let operation = AccountServiceRequest::ApplyExtended {
                        grant,
                        authorization,
                        request: Box::new(request.clone()),
                        update: update.clone(),
                    };
                    // Another member's session cannot submit this member's request.
                    let mut other = pseudonym;
                    other[0] ^= 1;
                    assert!(
                        service
                            .handle_for_member_authorized(&other, operation.clone(), authority())
                            .is_err()
                    );
                    let response =
                        service.handle_for_member_authorized(&pseudonym, operation, authority());
                    ledger = Some(service.into_ledger());
                    let AccountServiceResponse::ApplyExtended {
                        acceptance,
                        certificate,
                        ancestry,
                        ..
                    } = response?
                    else {
                        return Err(Error::InvalidInput);
                    };
                    records.accepted(member, &acceptance, ancestry.as_deref());
                    if matches!(update.effect, Effect::Change { .. }) {
                        spent = Some(SpentChange {
                            acceptance: acceptance.clone(),
                            request: request.clone(),
                            update: update.clone(),
                        });
                    }
                    Ok(json!({"request": request, "acceptance": acceptance,
                        "certificate": certificate, "ancestry": ancestry}))
                }
                "recordRecipient" => {
                    let world = world.as_mut().unwrap();
                    let pseudonym = pseudonym(&v);
                    let member = member(&v);
                    let now = v["now"].as_u64().unwrap();
                    let mut request = RecipientRequest {
                        community: sha2::Sha256::digest(world.community.as_bytes()).into(),
                        owner: sha2::Sha256::digest(pseudonym).into(),
                        recipient_key: records::recipient_key(member),
                        chat_public_key: B64.encode(&world.device.verifying_key().to_bytes()),
                        lineage_epoch: 0,
                        issued_at: now,
                        expires_at: now + 100,
                        signature: String::new(),
                    };
                    request.signature =
                        B64.encode(&world.device.sign(&recipient_bytes(&request)?).to_bytes());
                    let grant = world.grant(&pseudonym, now + 1000);
                    let authorization = world.authorize(&pseudonym, member, now + 1000);
                    let mut service =
                        AccountService::new(ledger.take().unwrap(), || now, 16 * 1024 * 1024)?;
                    let response = service.handle_for_member_authorized(
                        &pseudonym,
                        AccountServiceRequest::RegisterRecordRecipient {
                            grant,
                            authorization,
                            request: request.clone(),
                        },
                        authority(),
                    );
                    ledger = Some(service.into_ledger());
                    let AccountServiceResponse::RecordRecipient { recipient_key } = response?
                    else {
                        return Err(Error::InvalidInput);
                    };
                    assert_eq!(recipient_key, records::recipient_key(member));
                    Ok(json!({"request": request}))
                }
                "recordEpoch" => {
                    let now = v["now"].as_u64().unwrap();
                    let mut service =
                        AccountService::new(ledger.take().unwrap(), || now, 16 * 1024 * 1024)?;
                    let publication = service.publish_record_epoch(
                        v["policyEpoch"].as_u64().unwrap(),
                        v["periodSeconds"].as_u64().unwrap(),
                    );
                    ledger = Some(service.into_ledger());
                    let publication = publication?;
                    let descriptor = json!(publication.descriptor());
                    records.published(publication);
                    Ok(descriptor)
                }
                // Daily settlement for this world: a fresh fixture RSA key for the epoch of `now`.
                "settlement" => {
                    let now = v["now"].as_u64().unwrap();
                    let period = v["periodSeconds"].as_u64().unwrap();
                    let epoch = now / period;
                    let key = openssl::rsa::Rsa::generate(3072).unwrap();
                    let config = SettlementConfig {
                        epoch: cmbl::settlement::Epoch {
                            purpose: cmbl::settlement::Purpose::OutcomeDeposit,
                            community: world.as_ref().unwrap().community.clone(),
                            epoch,
                            valid_from: epoch * period * 1000,
                            valid_until: (epoch + 1) * period * 1000,
                            public_key_der: key.public_key_to_der().unwrap(),
                        },
                        policy_epoch: v["policyEpoch"].as_u64().unwrap(),
                        period_seconds: period,
                        quota: 4,
                        pending_capacity: 16,
                        issuance_members_capacity: 16,
                        room_epochs: Vec::new(),
                    };
                    let installed = ledger.as_mut().unwrap().activate_daily_settlement(
                        config,
                        &zeroize::Zeroizing::new(key.private_key_to_der().unwrap()),
                        INCARNATION.into(),
                        || now,
                    )?;
                    let value = json!({"epoch": installed.epoch, "periodSeconds": period});
                    settlement = Some(installed);
                    Ok(value)
                }
                // One verified native deposit staged through the anonymous service route; the
                // settlement pass comes from the member route under that member's session.
                "stage" => {
                    let world = world.as_mut().unwrap();
                    let epoch = settlement.as_ref().unwrap();
                    let now = v["now"].as_u64().unwrap();
                    let pseudonym = pseudonym(&v);
                    let member = member(&v);
                    let deposit: Deposit = serde_json::from_value(v["deposit"].clone()).unwrap();
                    let proof = HEXLOWER
                        .decode(v["proof"].as_str().unwrap().as_bytes())
                        .unwrap();
                    let digest = deposit_digest(&deposit)?;
                    let prepared =
                        cmbl::settlement::PreparedToken::new(epoch, digest, now * 1000).unwrap();
                    let mut request = SettlementPassRequest {
                        community: sha2::Sha256::digest(world.community.as_bytes()).into(),
                        owner: sha2::Sha256::digest(pseudonym).into(),
                        operation: [u8::try_from(v["operation"].as_u64().unwrap()).unwrap(); 16],
                        blind: prepared.request(),
                        issued_at: now,
                        expires_at: (now + 10).min(epoch.valid_until / 1000),
                        signature: String::new(),
                    };
                    request.signature = B64.encode(
                        &world
                            .device
                            .sign(&settlement_pass_request_bytes(&request)?)
                            .to_bytes(),
                    );
                    let grant = world.grant(&pseudonym, now + 1000);
                    let authorization = world.authorize(&pseudonym, member, now + 1000);
                    let mut service =
                        AccountService::new(ledger.take().unwrap(), || now, 16 * 1024 * 1024)?;
                    let pass = service.handle_for_member_authorized(
                        &pseudonym,
                        AccountServiceRequest::IssueSettlementPass {
                            grant,
                            authorization,
                            request: request.clone(),
                        },
                        authority(),
                    );
                    let staged = pass.and_then(|pass| {
                        let AccountServiceResponse::SettlementPass { pass } = pass else {
                            return Err(Error::InvalidInput);
                        };
                        let client = prepared.finalize(&pass, now * 1000).unwrap();
                        let submission = SettlementSubmission {
                            deposit,
                            proof,
                            operation: request.operation,
                            token_proof: client
                                .prove(
                                    &cmbl::settlement::Request {
                                        deposit: digest,
                                        operation: request.operation,
                                    },
                                    INCARNATION,
                                    now * 1000,
                                )
                                .unwrap(),
                        };
                        let staged =
                            service.handle_anonymous(AccountServiceRequest::StageSettlement {
                                submission: submission.clone(),
                            })?;
                        // An exact retry returns the same durable status, never a second fact.
                        let retried =
                            service.handle_anonymous(AccountServiceRequest::StageSettlement {
                                submission,
                            })?;
                        assert_eq!(
                            serde_json::to_value(&staged).unwrap(),
                            serde_json::to_value(&retried).unwrap()
                        );
                        Ok(staged)
                    });
                    ledger = Some(service.into_ledger());
                    let AccountServiceResponse::Settlement(status) = staged? else {
                        return Err(Error::InvalidInput);
                    };
                    Ok(json!({"status": status, "depositDigest": digest}))
                }
                // Member-only output (HPKE trial opening); the driver never retains it.
                "recordWitness" => Ok(records.witness(member(&v))),
                "issueRecordChallenge" | "checkEpochRecord" => {
                    records.handle(&v, &world.as_ref().unwrap().fixture, &mut ledger)
                }
                "binding" => Ok(json!(change_binding(
                    &PinChange::from(&v["change"]).change()
                )?)),
                // The completed spend: the ledger's historical reverification, the service
                // decoder and the stateless verifier all accept the exact evidence bytes.
                "pinSpend" => {
                    let pin = PinChange::from(&v["change"]);
                    let change = pin.change();
                    let token = spent.as_ref().unwrap();
                    let policy = extension_policy.as_ref().unwrap();
                    pin_spend::exercise(ledger.as_mut().unwrap(), &change, token, policy);
                    let (returned, _) = pin_spend::service(ledger.take().unwrap(), &change, token);
                    ledger = Some(returned);
                    let verifier = PinSpendVerifier {
                        operator_key: SigningKey::from_bytes(&[OPERATOR_SEED; 32])
                            .verifying_key()
                            .to_bytes(),
                        scope: scope.clone().unwrap(),
                        policy: policy.clone(),
                    };
                    futures::executor::block_on(async {
                        verifier.verify_spent(&change, token).await.unwrap();
                        let mut other = token.acceptance.clone();
                        other.signature = "invalid".into();
                        let damaged = SpentChange {
                            acceptance: other,
                            request: token.request.clone(),
                            update: token.update.clone(),
                        };
                        assert!(verifier.verify_spent(&change, &damaged).await.is_err());
                    });
                    Ok(
                        json!({"request": token.request, "acceptance": token.acceptance,
                        "update": token.update}),
                    )
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

/// Test authority: always current, and every device is in the lineage.
pub(crate) struct TestAuthority;
impl cblc::storage::CommitAuthority for TestAuthority {
    fn check(&self, _: u64) -> Result<(), cblc::Error> {
        Ok(())
    }
    fn boundary_crossed(&self, _: u64, _: u64) -> Result<bool, cblc::Error> {
        Ok(false)
    }
    fn lineage(&self) -> Option<&dyn cblc::current_device::CurrentLineage> {
        Some(&TestLineage)
    }
}
pub(crate) struct TestLineage;
impl cblc::current_device::CurrentLineage for TestLineage {
    fn is_current(&self, _: &[u8; 32]) -> bool {
        true
    }
}
pub(crate) fn authority() -> std::sync::Arc<dyn cblc::storage::CommitAuthority> {
    std::sync::Arc::new(TestAuthority)
}
