//! Existing original four-group witness outputs only; no accepting verifier.
use crate::{common, inspection};
use cblc::{
    Error,
    accounting::{AccountProofScope, AccountRequest, account_request_bytes},
    accounting_ledger::{AccountLedger, AccountLedgerPolicy},
    extensions::{
        Deposit, EXTENSION_PROOF_BYTES, ExtendedUpdate, ExtensionActivation, ExtensionPolicy,
    },
    settlement::{
        SettlementConfig, SettlementPassRequest, SettlementSubmission, deposit_digest,
        settlement_pass_request_bytes,
    },
    verification::{ExtensionLimits, NativeExtensionVerifier},
};
use cmbl::settlement::{Epoch, PreparedToken, Purpose, Request};
use common::{Fixture, proofs::RealVerifier};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
use ed25519_dalek::{Signer, SigningKey};
use hpke::{Kem as _, Serializable};
use openssl::rsa::Rsa;
use serde_json::Value;
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};
use zeroize::Zeroizing;

#[path = "settlement/cuts.rs"]
mod cuts;
#[path = "settlement/key_inventory.rs"]
mod key_inventory;
#[cfg(feature = "publication")]
#[path = "settlement/publication.rs"]
mod publication;

type Ledger = AccountLedger<RealVerifier>;
const PERIOD: u64 = 100;
const INCARNATION: &str = "native-settlement-fixture";

struct Inputs {
    directory: PathBuf,
    trace: Vec<Value>,
    init: Value,
    settings: AccountLedgerPolicy,
    extension: ExtensionPolicy,
    scope: AccountProofScope,
}
impl Inputs {
    fn load(name: &str) -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
        let trace: Vec<Value> =
            serde_json::from_slice(&std::fs::read(directory.join("public-trace.json")).unwrap())
                .unwrap();
        let init = trace
            .iter()
            .find(|value| value["request"]["op"] == "init" && value["response"]["ok"] == true)
            .unwrap()["request"]
            .clone();
        Self {
            directory,
            settings: AccountLedgerPolicy {
                account: serde_json::from_value(init["policy"].clone()).unwrap(),
                max_authorization_seconds: 100,
                max_proof_bytes: EXTENSION_PROOF_BYTES,
                checkpoint_period_seconds: 1000,
            },
            extension: serde_json::from_value(init["extension"].clone()).unwrap(),
            scope: serde_json::from_value(init["scope"].clone()).unwrap(),
            init,
            trace,
        }
    }
    fn open(&self, path: &Path, fixture: &Fixture) -> Ledger {
        let options = common::native::options(1024 * 1024);
        common::host_storage::open(
            path,
            fixture.trust.clone(),
            self.settings.clone(),
            RealVerifier::default(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap()
        .with_extensions(
            self.extension.clone(),
            NativeExtensionVerifier::new(
                options.clone(),
                options,
                common::native::extension(&self.directory),
            )
            .unwrap(),
            ExtensionLimits {
                global_burst: 1000,
                subject_burst: 500,
                replenish: Duration::from_secs(1),
                maximum_keys: NonZeroUsize::new(32).unwrap(),
            },
            ExtensionActivation {
                account: serde_json::from_value(self.init["activation"]["account"].clone())
                    .unwrap(),
                proof: HEXLOWER
                    .decode(
                        self.init["activation"]["proof"]
                            .as_str()
                            .unwrap()
                            .as_bytes(),
                    )
                    .unwrap(),
            },
        )
        .unwrap()
    }
    fn admit(&self, ledger: &mut Ledger, fixture: &Fixture) {
        ledger
            .admit_checkpoint(
                0,
                serde_json::from_value(self.init["root"].clone()).unwrap(),
            )
            .unwrap();
        let genesis: Vec<&Value> = self
            .trace
            .iter()
            .filter(|value| {
                value["request"]["op"] == "apply"
                    && value["request"]["statement"]["genesis"] == true
                    && value["response"]["ok"] == true
            })
            .take(4)
            .map(|value| &value["request"])
            .collect();
        assert_eq!(genesis.len(), 4);
        for value in genesis {
            let member = value["member"].as_u64().unwrap() as u8;
            let statement = serde_json::from_value(value["statement"].clone()).unwrap();
            let mut request = AccountRequest {
                issued_at: value["statement"]["now"].as_u64().unwrap(),
                expires_at: value["statement"]["validUntil"].as_u64().unwrap(),
                statement,
                request_id: [member; 32],
                proof_scope: self.scope.clone(),
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
            let update: ExtendedUpdate = serde_json::from_value(value["update"].clone()).unwrap();
            ledger
                .apply_extended(
                    &fixture.grant(member, &fixture.device),
                    &fixture.authorize(member, &fixture.device),
                    &request,
                    &update,
                    || request.issued_at,
                )
                .unwrap();
        }
        for member in 7..11 {
            type Kem = hpke::kem::X25519HkdfSha256;
            let (_, public) = Kem::derive_keypair(&[member; 32]);
            let mut request = cblc::accounting_ledger::record_epoch::RecipientRequest {
                community: self.community(),
                owner: owner(member),
                recipient_key: public.to_bytes().as_slice().try_into().unwrap(),
                chat_public_key: B64.encode(&fixture.device.verifying_key().to_bytes()),
                issued_at: 114,
                expires_at: 190,
                signature: String::new(),
            };
            request.signature = B64.encode(
                &fixture
                    .device
                    .sign(
                        &cblc::accounting_ledger::record_epoch::recipient_bytes(&request).unwrap(),
                    )
                    .to_bytes(),
            );
            ledger
                .register_record_recipient(
                    &fixture.grant(member, &fixture.device),
                    &fixture.authorize(member, &fixture.device),
                    &request,
                    || 114,
                )
                .unwrap();
        }
    }
    fn community(&self) -> [u8; 32] {
        serde_json::from_value(self.init["activation"]["account"]["community"].clone()).unwrap()
    }
    fn deposits(&self) -> (u64, Vec<(Deposit, Vec<u8>)>) {
        let request = &self
            .trace
            .iter()
            .find(|value| value["request"]["op"] == "deposit" && value["response"]["ok"] == true)
            .expect("genuine four-group ingestion Deposit trace required")["request"];
        let deposits = request["batch"]
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
            .collect::<Vec<_>>();
        assert_eq!(deposits.len(), 2);
        (request["now"].as_u64().unwrap(), deposits)
    }
}

fn private_key(next: bool) -> &'static [u8] {
    static FIRST: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();
    static NEXT: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();
    (if next { &NEXT } else { &FIRST })
        .get_or_init(|| Zeroizing::new(Rsa::generate(3072).unwrap().private_key_to_der().unwrap()))
}
fn config(epoch: u64, next: bool, pending: u32, members: u32) -> SettlementConfig {
    SettlementConfig {
        epoch: Epoch {
            purpose: Purpose::OutcomeDeposit,
            community: "community.example".into(),
            epoch,
            valid_from: epoch * PERIOD * 1000,
            valid_until: (epoch + 1) * PERIOD * 1000,
            public_key_der: Rsa::private_key_from_der(private_key(next))
                .unwrap()
                .public_key_to_der()
                .unwrap(),
        },
        policy_epoch: 1,
        period_seconds: PERIOD,
        quota: 4,
        pending_capacity: pending,
        issuance_members_capacity: members,
        room_epochs: Vec::new(),
    }
}
fn owner(member: u8) -> [u8; 32] {
    B64.decode(common::member_id(member).as_bytes())
        .unwrap()
        .try_into()
        .unwrap()
}
fn pass_request(
    fixture: &Fixture,
    epoch: &Epoch,
    digest: [u8; 32],
    member: u8,
    operation: u8,
    now: u64,
) -> (PreparedToken, SettlementPassRequest) {
    let prepared = PreparedToken::new(epoch, digest, now * 1000).unwrap();
    let mut request = SettlementPassRequest {
        community: sha2_community(),
        owner: owner(member),
        operation: [operation; 16],
        blind: prepared.request(),
        issued_at: now,
        expires_at: (now + 10).min(epoch.valid_until / 1000),
        signature: String::new(),
    };
    request.signature = B64.encode(
        &fixture
            .device
            .sign(&settlement_pass_request_bytes(&request).unwrap())
            .to_bytes(),
    );
    (prepared, request)
}
fn sha2_community() -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b"community.example").into()
}
fn record_key(kind: u8, value: &[u8; 32]) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&32_u64.to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}
fn submission(
    ledger: &mut Ledger,
    fixture: &Fixture,
    epoch: &Epoch,
    deposit: &Deposit,
    proof: &[u8],
    operation: u8,
    now: u64,
) -> SettlementSubmission {
    let digest = deposit_digest(deposit).unwrap();
    let (prepared, request) = pass_request(fixture, epoch, digest, 7, operation, now);
    let signature = ledger
        .issue_settlement_pass(
            &fixture.grant(7, &fixture.device),
            &fixture.authorize(7, &fixture.device),
            &request,
            || now,
        )
        .unwrap();
    let client = prepared.finalize(&signature, now * 1000).unwrap();
    SettlementSubmission {
        deposit: deposit.clone(),
        proof: proof.to_vec(),
        operation: request.operation,
        token_proof: client
            .prove(
                &Request {
                    deposit: digest,
                    operation: request.operation,
                },
                INCARNATION,
                now * 1000,
            )
            .unwrap(),
    }
}
fn activate(ledger: &mut Ledger, cfg: &SettlementConfig, next: bool, now: u64) {
    eprintln!(
        "DIAG context={:?} publen={} keylen={}",
        cfg.epoch.context().map(|_| ()),
        cfg.epoch.public_key_der.len(),
        private_key(next).len(),
    );
    assert!(
        ledger
            .activate_daily_settlement(cfg.clone(), private_key(next), INCARNATION.into(), || now)
            .unwrap()
            == cfg.epoch
    );
}

#[test]
fn actual_three_key_group_cannot_activate_a_daily_queue() {
    let inputs = Inputs::load(".extension-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("legacy.db");
    let mut ledger = inputs.open(&path, &fixture);
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    assert!(matches!(
        ledger.activate_daily_settlement(
            config(1, false, 8, 8),
            private_key(false),
            INCARNATION.into(),
            || 100
        ),
        Err(Error::UnsupportedCapability)
    ));
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
}

#[test]
fn new_member_at_capacity_refuses_without_poisoning_exact_owner_retry() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("capacity.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 1);
    activate(&mut ledger, &cfg, false, 100);
    inputs.admit(&mut ledger, &fixture);
    let (prepared, first) = pass_request(&fixture, &cfg.epoch, [7; 32], 7, 1, 114);
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    let mut altered = first.clone();
    altered.operation = [3; 16];
    assert!(
        ledger
            .issue_settlement_pass(
                &fixture.grant(7, &fixture.device),
                &fixture.authorize(7, &fixture.device),
                &altered,
                || 114
            )
            .is_err()
    );
    let mut wrong_epoch = fixture.grant(7, &fixture.device);
    wrong_epoch.policy_epoch = 2;
    fixture.resign_grant(&mut wrong_epoch);
    assert_eq!(
        ledger.issue_settlement_pass(
            &wrong_epoch,
            &fixture.authorize(7, &fixture.device),
            &first,
            || 114
        ),
        Err(Error::Admission)
    );
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    let signature = ledger
        .issue_settlement_pass(
            &fixture.grant(7, &fixture.device),
            &fixture.authorize(7, &fixture.device),
            &first,
            || 114,
        )
        .unwrap();
    prepared.finalize(&signature, 114_000).unwrap();
    let (_, second) = pass_request(&fixture, &cfg.epoch, [8; 32], 8, 2, 114);
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    assert_eq!(
        ledger.issue_settlement_pass(
            &fixture.grant(8, &fixture.device),
            &fixture.authorize(8, &fixture.device),
            &second,
            || 114
        ),
        Err(Error::Capacity)
    );
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    assert_eq!(
        ledger
            .issue_settlement_pass(
                &fixture.grant(7, &fixture.device),
                &fixture.authorize(7, &fixture.device),
                &first,
                || 114
            )
            .unwrap(),
        signature
    );
    let rows = inspection::Connection::open(&path).unwrap().snapshot();
    assert_eq!(
        rows.iter()
            .filter(|(key, _)| key.starts_with(b"settlement-budget:"))
            .count(),
        1
    );
    let anchor = rows
        .iter()
        .find(|(key, _)| key.starts_with(b"settlement-issuer:"))
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&anchor.1).unwrap()["issued"],
        1
    );
    // Losing the original owner row cannot replenish its quota: the durable
    // issued-count anchor must still equal the complete validated receipt sum.
    let budget = rows
        .iter()
        .find(|(key, _)| key.starts_with(b"settlement-budget:"))
        .unwrap();
    let connection = inspection::Connection::open(&path).unwrap();
    connection
        .execute_batch(&format!(
            "DELETE FROM cssr_records WHERE community_id='community.example' AND key=X'{}'",
            HEXLOWER.encode(&budget.0)
        ))
        .unwrap();
    let missing = connection.snapshot();
    assert_eq!(
        ledger.issue_settlement_pass(
            &fixture.grant(7, &fixture.device),
            &fixture.authorize(7, &fixture.device),
            &first,
            || 114
        ),
        Err(Error::Storage)
    );
    assert_eq!(connection.snapshot(), missing);
    connection.execute_batch(&format!("INSERT INTO cssr_records(community_id,key,value) VALUES('community.example',X'{}',X'{}')",
        HEXLOWER.encode(&budget.0), HEXLOWER.encode(&budget.1))).unwrap();
    assert_eq!(
        ledger
            .issue_settlement_pass(
                &fixture.grant(7, &fixture.device),
                &fixture.authorize(7, &fixture.device),
                &first,
                || 114
            )
            .unwrap(),
        signature
    );
}
