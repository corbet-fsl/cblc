//! Test-only original HPKE/tree/certificate owner fixture, never proof authority.
use cblc::{
    Error,
    accounting::AccountProofVerifier,
    accounting_ledger::{AccountLedger, record_epoch},
    accounting_service::{AccountService, AccountServiceRequest, AccountServiceResponse},
    extensions::{RecordChallenge, RecordContext},
};
use cblc::{
    accounting::AccountAcceptance, accounting_ledger::record_epoch::RecordEpochPublication,
    extensions::EpochAncestryCertificate,
};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::Signer as _;
use hpke::{Deserializable, Kem as _, Serializable};
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::BTreeMap;

#[cfg(feature = "publication")]
#[path = "record-epoch-relying.rs"]
mod relying;

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
    let record_leaf = certificate
        .record
        .leaf
        .commitment(&epoch.community, epoch.epoch)
        .unwrap();
    czkp::record::verify_certificate(
        &epoch.issuer_key,
        &epoch.community,
        epoch.epoch,
        &record_leaf,
        &certificate.record.signature,
    )
    .unwrap();
    assert_eq!(certificate.record.leaf.owner, accepted.statement.owner);
    assert!(certificate.record.leaf.version <= accepted.statement.next_version);
    let (leaf, _, _, _) = open_witness(publication, member);
    assert_eq!(leaf.owner, accepted.statement.owner);
    assert_eq!(
        leaf.commitment(&epoch.community, epoch.epoch).unwrap(),
        certificate.frozen_leaf
    );
}

pub fn open_witness(
    publication: &RecordEpochPublication,
    member: u8,
) -> (czkp::record::Leaf, u32, Vec<[u8; 32]>, Vec<u8>) {
    let epoch = publication.descriptor();
    // Independently open the member's packet from the real common object and
    // verify the leaf path. No issuer-internal leaf accessor is used.
    let prefix = b"cblc.record-witnesses.v2\0";
    let object = publication.common_object();
    assert_eq!(&object[..prefix.len()], prefix);
    let packet_size = u32::from_be_bytes(
        object[prefix.len() + 4..prefix.len() + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let aad = serde_json::to_vec(&serde_json::json!([
        "cblc.record-packet.v2",
        epoch.community,
        epoch.policy_epoch,
        epoch.epoch,
        epoch.starts_at,
        epoch.expires_at,
        epoch.root,
        epoch.issuer_key,
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
                b"cblc.record-witness.v2\0",
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
        bytes[140..bytes.len() - 64].as_chunks::<32>().0.to_vec(),
    );
    assert!(path.verify(
        epoch.root,
        &[index],
        &[hash],
        (epoch.leaf_count as usize).max(2).next_power_of_two()
    ));
    let certificate = bytes[bytes.len() - 64..].to_vec();
    czkp::record::verify_certificate(
        &epoch.issuer_key,
        &epoch.community,
        epoch.epoch,
        &hash,
        &certificate,
    )
    .unwrap();
    (
        leaf,
        index as u32,
        path.proof_hashes().to_vec(),
        certificate,
    )
}

#[derive(Default)]
pub struct Records {
    publication: Option<RecordEpochPublication>,
    latest: BTreeMap<u8, Option<EpochAncestryCertificate>>,
    challenges: BTreeMap<[u8; 32], RecordChallenge>,
}
impl Records {
    pub fn handle<V: AccountProofVerifier>(
        &mut self,
        v: &Value,
        fixture: &crate::common::Fixture,
        ledger: &mut Option<AccountLedger<V>>,
    ) -> Result<Value, Error> {
        match v["op"].as_str().unwrap() {
            "recordFixtureMaterial" => {
                #[cfg(feature = "publication")]
                {
                    relying::export(v, fixture, ledger.as_mut().unwrap())
                }
                #[cfg(not(feature = "publication"))]
                {
                    Err(Error::UnsupportedCapability)
                }
            }
            "verifyPublishedRecord" => {
                #[cfg(feature = "publication")]
                {
                    relying::check(v, fixture, ledger.as_mut().unwrap())
                }
                #[cfg(not(feature = "publication"))]
                {
                    Err(Error::UnsupportedCapability)
                }
            }
            "recordRecipient" => {
                let member = v["member"].as_u64().unwrap() as u8;
                let now = v["now"].as_u64().unwrap();
                let mut request = record_epoch::RecipientRequest {
                    community: sha2::Sha256::digest(fixture.trust.community_id.as_bytes()).into(),
                    owner: sha2::Sha256::digest([member; 48]).into(),
                    recipient_key: recipient_key(member),
                    chat_public_key: B64.encode(&fixture.device.verifying_key().to_bytes()),
                    issued_at: now,
                    expires_at: now + 100,
                    signature: String::new(),
                };
                request.signature = B64.encode(
                    &fixture
                        .device
                        .sign(&record_epoch::recipient_bytes(&request)?)
                        .to_bytes(),
                );
                let mut service =
                    AccountService::new(ledger.take().unwrap(), || now, 16 * 1024 * 1024)?;
                let response = service.handle_for_member(
                    &[member; 48],
                    AccountServiceRequest::RegisterRecordRecipient {
                        grant: fixture.grant(member, &fixture.device),
                        authorization: fixture.authorize(member, &fixture.device),
                        request,
                    },
                );
                *ledger = Some(service.into_ledger());
                let AccountServiceResponse::RecordRecipient {
                    recipient_key: registered_key,
                } = response?
                else {
                    return Err(Error::InvalidInput);
                };
                assert_eq!(registered_key, recipient_key(member));
                Ok(json!(true))
            }
            "recordEpoch" => {
                let now = v["now"].as_u64().unwrap();
                let mut service =
                    AccountService::new(ledger.take().unwrap(), || now, 16 * 1024 * 1024)?;
                let publication = service.publish_record_epoch(1, 100);
                *ledger = Some(service.into_ledger());
                self.published(publication?);
                Ok(json!(true))
            }
            "recordWitness" => {
                // Member-only fixture output from actual HPKE trial opening.
                // The TypeScript driver never retains this in public evidence.
                Ok(self.witness(v["member"].as_u64().unwrap() as u8))
            }
            "issueRecordChallenge" => {
                let owner = serde_json::from_value(v["owner"].clone()).unwrap();
                let context: RecordContext = serde_json::from_value(v["context"].clone()).unwrap();
                let id = context.challenge;
                if self.challenges.contains_key(&id) {
                    return Err(Error::Replay);
                }
                self.challenges
                    .insert(id, RecordChallenge::new(owner, context)?);
                Ok(json!(true))
            }
            "checkEpochRecord" => {
                let presentation: czkp::record::Presentation =
                    serde_json::from_value(v["presentation"].clone()).unwrap();
                let id: [u8; 32] = serde_json::from_value(v["challenge"].clone()).unwrap();
                let challenge = self.challenges.get_mut(&id).ok_or(Error::Admission)?;
                Ok(json!(ledger.as_mut().unwrap().check_epoch_record(
                    challenge,
                    &presentation,
                    || v["now"].as_u64().unwrap()
                )?))
            }
            _ => Err(Error::InvalidInput),
        }
    }
    pub fn published(&mut self, publication: RecordEpochPublication) {
        publication
            .descriptor()
            .check_object(publication.common_object())
            .unwrap();
        if let Some(previous) = &self.publication
            && previous.descriptor().epoch == publication.descriptor().epoch
        {
            assert_eq!(previous.descriptor(), publication.descriptor());
            assert_eq!(previous.common_object(), publication.common_object());
        }
        self.publication = Some(publication);
    }
    pub fn accepted(
        &mut self,
        member: u8,
        accepted: &AccountAcceptance,
        ancestry: Option<&EpochAncestryCertificate>,
    ) {
        if let Some(certificate) = ancestry {
            check_certificate(
                self.publication.as_ref().unwrap(),
                member,
                accepted,
                certificate,
            );
        }
        self.latest.insert(member, ancestry.cloned());
    }
    pub fn witness(&self, member: u8) -> Value {
        let publication = self.publication.as_ref().unwrap();
        let (leaf, index, path, certificate) = open_witness(publication, member);
        json!({"epoch":publication.descriptor(), "leaf":leaf, "index":index,
            "path":path, "certificate":certificate, "ancestry":self.latest.get(&member).unwrap()})
    }
}
