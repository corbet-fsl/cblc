//! Genuine issuer fixture helpers. Real libSQL and P-256/HPKE remain in use;
//! the storage wrapper only schedules another writer or refuses a commit.
use cblc::{
    accounting::AccountAcceptance, accounting_ledger::record_epoch::RecordEpochPublication,
    extensions::EpochAncestryCertificate,
};
use ed25519_dalek::Signer as _;
use hpke::{Deserializable, Kem as _, Serializable};
use std::sync::{Arc, Mutex};

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

pub fn recipient_key(member: u8) -> [u8; 32] {
    Kem::derive_keypair(&[member; 32])
        .1
        .to_bytes()
        .as_slice()
        .try_into()
        .unwrap()
}

pub fn check_certificate(
    publication: &RecordEpochPublication,
    member: u8,
    accepted: &AccountAcceptance,
    certificate: &EpochAncestryCertificate,
) {
    let epoch = publication.descriptor();
    assert_eq!(certificate.community, accepted.statement.community);
    assert_eq!(certificate.owner, accepted.statement.owner);
    assert_eq!(certificate.state, accepted.statement.next_state);
    assert_eq!(certificate.version, accepted.statement.next_version);
    assert_eq!(certificate.proof_scope, accepted.proof_scope);
    assert_eq!(certificate.issued_at, accepted.accepted_at);
    assert_eq!(certificate.epoch, epoch.epoch);
    assert_eq!(certificate.root, epoch.root);
    let key = cssr::certificate::CertificateIssuer::new(&[3; 32])
        .unwrap()
        .public_key();
    cssr::certificate::verify_ancestry(
        &key,
        &certificate.body(),
        certificate.signature.as_slice().try_into().unwrap(),
    )
    .unwrap();
    let (leaf, _, _) = open_witness(publication, member);
    assert_eq!(leaf.owner, accepted.statement.owner);
    assert_eq!(
        leaf.commitment(&epoch.community, epoch.epoch).unwrap(),
        certificate.frozen_leaf
    );
}

pub fn open_witness(
    publication: &RecordEpochPublication,
    member: u8,
) -> (czkp::record::Leaf, u32, Vec<[u8; 32]>) {
    let epoch = publication.descriptor();
    // Independently open the member's packet from the real common object and
    // verify the leaf path. No issuer-internal leaf accessor is used.
    let prefix = b"cblc.record-witnesses.v1\0";
    let object = publication.common_object();
    assert_eq!(&object[..prefix.len()], prefix);
    let packet_size = u32::from_be_bytes(
        object[prefix.len() + 4..prefix.len() + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let aad = serde_json::to_vec(&serde_json::json!([
        "cblc.record-packet.v1",
        epoch.community,
        epoch.policy_epoch,
        epoch.epoch,
        epoch.starts_at,
        epoch.expires_at,
        epoch.root,
        epoch.proof_scope,
        epoch.leaf_count,
        epoch.download_bytes,
    ]))
    .unwrap();
    let private = Kem::derive_keypair(&[member; 32]).0;
    let plaintexts: Vec<_> = object[prefix.len() + 8..]
        .chunks_exact(packet_size)
        .filter_map(|packet| {
            let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&packet[..32]).unwrap();
            hpke::single_shot_open::<Aead, Kdf, Kem>(
                &hpke::OpModeR::Base,
                &private,
                &enc,
                b"cblc.record-witness.v1\0",
                &packet[32..],
                &aad,
            )
            .ok()
        })
        .collect();
    assert_eq!(plaintexts.len(), 1);
    let bytes = &plaintexts[0];
    let leaf = czkp::record::Leaf {
        owner: bytes[0..32].try_into().unwrap(),
        version: u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
        state: bytes[40..72].try_into().unwrap(),
        required_inbox: bytes[72..104].try_into().unwrap(),
        blinding: bytes[104..136].try_into().unwrap(),
    };
    let hash = leaf.commitment(&epoch.community, epoch.epoch).unwrap();
    let index = u32::from_be_bytes(bytes[136..140].try_into().unwrap()) as usize;
    let path = rs_merkle::MerkleProof::<czkp::record::EpochTree>::new(
        bytes[140..]
            .chunks_exact(32)
            .map(|b| b.try_into().unwrap())
            .collect(),
    );
    assert!(path.verify(
        epoch.root,
        &[index],
        &[hash],
        (epoch.leaf_count as usize).max(2).next_power_of_two()
    ));
    (leaf, index as u32, path.proof_hashes().to_vec())
}

/// Reuse a genuine signed request/proof against damaged private storage. Each
/// refusal must roll back the real consumption/CAS; restore only the test fault.
pub fn refuse_corrupt_bindings<V: cblc::accounting::AccountProofVerifier>(
    ledger: &mut cblc::accounting_ledger::AccountLedger<V>,
    store: &mut cssr::LibsqlStore,
    operation: &cblc::accounting_service::AccountServiceRequest,
) {
    let cblc::accounting_service::AccountServiceRequest::ApplyExtended {
        grant,
        authorization,
        request,
        update,
    } = operation
    else {
        panic!("expected extended request")
    };
    let issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    let mut damaged = request.as_ref().clone();
    let mut bundle: serde_json::Value = serde_json::from_slice(&damaged.proof).unwrap();
    let original = bundle["proofs"][0]["proof"].as_str().unwrap();
    bundle["proofs"][0]["proof"] = serde_json::json!(format!(
        "{}{}",
        if original.starts_with('0') { '1' } else { '0' },
        &original[1..]
    ));
    damaged.proof = serde_json::to_vec(&bundle).unwrap();
    damaged.signature = data_encoding::BASE64URL_NOPAD.encode(
        &ed25519_dalek::SigningKey::from_bytes(&[2; 32])
            .sign(&cblc::accounting::account_request_bytes(&damaged).unwrap())
            .to_bytes(),
    );
    assert!(
        ledger
            .apply_extended_certified(grant, authorization, &damaged, update, &issuer, || request
                .issued_at)
            .is_err()
    );
    assert!(matches!(
        ledger.apply_extended_certified(
            grant,
            authorization,
            request,
            update,
            &cssr::certificate::CertificateIssuer::new(&[4; 32]).unwrap(),
            || request.issued_at
        ),
        Err(cblc::Error::PolicyMismatch)
    ));
    for variant in 0..9 {
        let key = if variant < 4 {
            b"record-epoch-anchor:v1".to_vec()
        } else {
            [
                vec![1],
                32_u64.to_be_bytes().to_vec(),
                request.statement.owner.to_vec(),
            ]
            .concat()
        };
        let mut tx = cssr::Storage::transaction(store).unwrap();
        let original = tx.get(&key).unwrap().unwrap();
        let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
        let pointer = match variant {
            0 => "/configuration/0",
            1 => "/extension_configuration/0",
            2 => "/descriptor/proofScope/verifyingKeyDigest/0",
            3 => "/frozen_at",
            4 => "/record_ancestry/epoch",
            5 => "/record_ancestry/leaf/owner/0",
            6 => "/record_ancestry/leaf/blinding/0",
            7 => "/record_ancestry/path/0/0",
            _ => "/record_ancestry/index",
        };
        let value = changed.pointer_mut(pointer).unwrap();
        *value = serde_json::json!(match variant {
            3 => request.issued_at + 1,
            4 => value.as_u64().unwrap() + 1,
            8 => u64::from(u32::MAX),
            _ => value.as_u64().unwrap() ^ 1,
        });
        tx.put(&key, &serde_json::to_vec(&changed).unwrap())
            .unwrap();
        tx.commit().unwrap();
        assert!(
            ledger
                .apply_extended_certified(grant, authorization, request, update, &issuer, || {
                    request.issued_at
                })
                .is_err(),
            "corrupt ancestry case {variant}"
        );
        let mut tx = cssr::Storage::transaction(store).unwrap();
        tx.put(&key, &original).unwrap();
        tx.commit().unwrap();
    }
}

#[derive(Default)]
pub struct Controls {
    pub fail_acceptance: bool,
    pub fail_publication: bool,
    pub failed_with_certificate: bool,
    // Number of transactions to allow before running an independent writer,
    // outside every store lock. The service uses reload, preflight, final CAS.
    pub before_transaction: Option<(usize, Box<dyn FnOnce() + Send>)>,
}
pub type Control = Arc<Mutex<Controls>>;
pub struct FaultStore {
    pub inner: cssr::LibsqlStore,
    pub control: Control,
}
impl cssr::Storage for FaultStore {
    fn transaction(&mut self) -> cssr::Result<Box<dyn cssr::Transaction + '_>> {
        let action = {
            let mut control = self.control.lock().unwrap();
            match control.before_transaction.as_mut() {
                Some((0, _)) => control.before_transaction.take().map(|(_, action)| action),
                Some((remaining, _)) => {
                    *remaining -= 1;
                    None
                }
                None => None,
            }
        };
        if let Some(action) = action {
            action();
        }
        Ok(Box::new(FaultTransaction {
            inner: cssr::Storage::transaction(&mut self.inner)?,
            control: self.control.clone(),
            wrote_acceptance: false,
            wrote_certificate: false,
            wrote_publication: false,
        }))
    }
}
struct FaultTransaction<'a> {
    inner: Box<dyn cssr::Transaction + 'a>,
    control: Control,
    wrote_acceptance: bool,
    wrote_certificate: bool,
    wrote_publication: bool,
}
impl cssr::Transaction for FaultTransaction<'_> {
    fn get(&mut self, key: &[u8]) -> cssr::Result<Option<Vec<u8>>> {
        self.inner.get(key)
    }
    fn current_range(
        &mut self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> cssr::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.inner.current_range(start, end, limit)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> cssr::Result<()> {
        self.wrote_acceptance |= key.first() == Some(&2);
        self.wrote_certificate |= key.starts_with(b"record-ancestry-latest:v1:");
        self.wrote_publication |= key == b"record-epoch-anchor:v1";
        self.inner.put(key, value)
    }
    fn delete(&mut self, key: &[u8]) -> cssr::Result<()> {
        self.inner.delete(key)
    }
    fn rollback(self: Box<Self>) -> cssr::Result<()> {
        self.inner.rollback()
    }
    fn commit(self: Box<Self>) -> cssr::Result<()> {
        let mut control = self.control.lock().unwrap();
        if self.wrote_publication && control.fail_publication {
            control.fail_publication = false;
            return Err(cssr::Error);
        }
        if self.wrote_acceptance && control.fail_acceptance {
            control.fail_acceptance = false;
            control.failed_with_certificate = self.wrote_certificate;
            return Err(cssr::Error);
        }
        drop(control);
        self.inner.commit()
    }
}
