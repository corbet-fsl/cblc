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
            issuer_public_key: issuer.verifying_key().to_bytes(),
        };
        Self {
            issuer,
            device,
            trust,
        }
    }
    pub fn grant(&self, member: u8, device: &SigningKey) -> AdmissionGrant {
        let mut grant = AdmissionGrant {
            version: 2,
            issuer_key_id: BASE64URL_NOPAD
                .encode(&Sha256::digest(self.issuer.verifying_key().to_bytes())),
            community_id: self.trust.community_id.clone(),
            member_id: member_id(member),
            pseudonym: data_encoding::HEXLOWER.encode(&[member; 48]),
            chat_public_key: BASE64URL_NOPAD.encode(&device.verifying_key().to_bytes()),
            policy_digest: self.trust.policy_digest.clone(),
            issued_at: 100,
            expires_at: 1000,
            signature: String::new(),
        };
        // Independent fixture construction: do not use the library encoder to sign.
        let bytes = serde_json::to_vec(&serde_json::json!([
            "cvld.admission.v2",
            grant.issuer_key_id,
            grant.community_id,
            grant.member_id,
            grant.pseudonym,
            grant.chat_public_key,
            grant.policy_digest,
            grant.issued_at,
            grant.expires_at
        ]))
        .unwrap();
        grant.signature = BASE64URL_NOPAD.encode(&self.issuer.sign(&bytes).to_bytes());
        grant
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
