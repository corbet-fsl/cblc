#[allow(dead_code)]
pub mod host_storage;
pub mod native;
pub mod proofs;
use cblc::admission::{AdmissionGrant, AdmissionTrust, DeviceAuthorization};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

pub fn encoded(value: u8) -> String {
    BASE64URL_NOPAD.encode(&[value; 32])
}

pub fn member_id(member: u8) -> String {
    // Synthetic canonical-length pseudonym bytes, independent of the root key.
    BASE64URL_NOPAD.encode(&Sha256::digest([member; 48]))
}

pub struct Fixture {
    pub issuer: SigningKey,
    pub device: SigningKey,
    pub trust: AdmissionTrust,
}

impl Fixture {
    pub fn new() -> Self {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let device = SigningKey::from_bytes(&[2; 32]);
        let trust = AdmissionTrust {
            community_id: "community.example".into(),
            policy_digest: encoded(3),
            policy_keys: csgn::Signer::new(
                "community.example",
                csgn::SecretKey::from_seed(&mut [1; 32]),
                0,
                100_000,
            )
            .unwrap()
            .key_ring()
            .clone(),
        };
        Self {
            issuer,
            device,
            trust,
        }
    }
    pub fn grant(&self, member: u8, device: &SigningKey) -> AdmissionGrant {
        let mut grant = AdmissionGrant {
            version: 3,
            issuer_key_id: BASE64URL_NOPAD
                .encode(&Sha256::digest(self.issuer.verifying_key().to_bytes())),
            community_id: self.trust.community_id.clone(),
            member_id: member_id(member),
            pseudonym: data_encoding::HEXLOWER.encode(&[member; 48]),
            chat_public_key: BASE64URL_NOPAD.encode(&device.verifying_key().to_bytes()),
            policy_digest: self.trust.policy_digest.clone(),
            policy_epoch: 1,
            passport_policy_digest: encoded(10),
            issued_at: 100,
            expires_at: 1000,
            signature: String::new(),
        };
        // Preserve the independently constructed fixture transcript and require
        // exact agreement with the owner encoder before signing.
        let bytes = serde_json::to_vec(&serde_json::json!([
            "cvld.admission.v3",
            grant.issuer_key_id,
            grant.community_id,
            grant.member_id,
            grant.pseudonym,
            grant.chat_public_key,
            grant.policy_digest,
            grant.policy_epoch,
            grant.passport_policy_digest,
            grant.issued_at,
            grant.expires_at
        ]))
        .unwrap();
        assert_eq!(cblc::admission::admission_bytes(&grant).unwrap(), bytes);
        self.resign_grant(&mut grant);
        grant
    }
    pub fn sign_admission_payload(&self, bytes: &[u8], issued: u64, until: u64) -> String {
        let mut signer = csgn::Signer::new(
            &self.trust.community_id,
            csgn::SecretKey::from_seed(&mut [1; 32]),
            0,
            100_000,
        )
        .unwrap();
        BASE64URL_NOPAD.encode(
            &signer
                .sign(csgn::Kind::Credential, bytes, issued, until)
                .unwrap(),
        )
    }
    pub fn resign_grant(&self, grant: &mut AdmissionGrant) {
        grant.signature = self.sign_admission_payload(
            &cblc::admission::admission_bytes(grant).unwrap(),
            grant.issued_at,
            grant.expires_at,
        );
    }
    pub fn authorize(&self, member: u8, device: &SigningKey) -> DeviceAuthorization {
        let root = SigningKey::from_bytes(&[member; 32]);
        let mut authorization = DeviceAuthorization {
            version: 1,
            community_id: self.trust.community_id.clone(),
            member_id: member_id(member),
            root_public_key: BASE64URL_NOPAD.encode(&root.verifying_key().to_bytes()),
            device_public_key: BASE64URL_NOPAD.encode(&device.verifying_key().to_bytes()),
            issued_at: 100,
            expires_at: 900,
            signature: String::new(),
        };
        let bytes = serde_json::to_vec(&serde_json::json!([
            "cmsg.device.v1",
            authorization.community_id,
            authorization.member_id,
            authorization.root_public_key,
            authorization.device_public_key,
            authorization.issued_at,
            authorization.expires_at
        ]))
        .unwrap();
        authorization.signature = BASE64URL_NOPAD.encode(&root.sign(&bytes).to_bytes());
        authorization
    }
}
