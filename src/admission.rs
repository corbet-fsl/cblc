use crate::Error;
use czkp::digest;
pub(crate) use czkp::{MAX_INTEGER, decode, scope, signature};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionGrant {
    pub version: u32,
    pub issuer_key_id: String,
    pub community_id: String,
    pub member_id: String,
    /// Canonical cpsd pseudonym bytes in lowercase hex, authenticated by the issuer.
    pub pseudonym: String,
    pub chat_public_key: String,
    pub policy_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct AdmissionTrust {
    pub community_id: String,
    pub policy_digest: String,
    pub issuer_public_key: [u8; 32],
}

/// Existing external eligibility wire format; cfrm holds only issuer public keys.
pub fn admission_bytes(grant: &AdmissionGrant) -> Result<Vec<u8>, Error> {
    if grant.version != 2
        || !scope(&grant.community_id)
        || grant.issued_at == 0
        || grant.issued_at >= grant.expires_at
        || grant.expires_at > MAX_INTEGER
    {
        return Err(Error::Admission);
    }
    let pseudonym: [u8; 48] = data_encoding::HEXLOWER
        .decode(grant.pseudonym.as_bytes())
        .map_err(|_| Error::Admission)?
        .try_into()
        .map_err(|_| Error::Admission)?;
    // HEXLOWER already rejects every noncanonical symbol and length.
    if member_id(&pseudonym) != grant.member_id {
        return Err(Error::Admission);
    }
    for value in [
        &grant.issuer_key_id,
        &grant.member_id,
        &grant.chat_public_key,
        &grant.policy_digest,
    ] {
        decode::<32>(value).map_err(|_| Error::Admission)?;
    }
    serde_json::to_vec(&serde_json::json!([
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
    .map_err(|_| Error::Admission)
}

pub fn verify_admission(
    grant: &AdmissionGrant,
    trust: &AdmissionTrust,
    now: u64,
) -> Result<(), Error> {
    let bytes = admission_bytes(grant)?;
    if grant.community_id != trust.community_id
        || grant.policy_digest != trust.policy_digest
        || grant.issuer_key_id != digest(&trust.issuer_public_key)
        || now < grant.issued_at
        || now >= grant.expires_at
    {
        return Err(Error::Admission);
    }
    signature(
        &BASE64URL_NOPAD.encode(&trust.issuer_public_key),
        &bytes,
        &grant.signature,
    )
    .map_err(|_| Error::Admission)
}

/// Member-owned root authorization. Eligibility issuers cannot create this proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceAuthorization {
    pub version: u32,
    pub community_id: String,
    pub member_id: String,
    pub root_public_key: String,
    pub device_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// Account owner: SHA-256 of the canonical 48-byte community pseudonym returned
/// by cpsd verification. This function is an encoding adapter, not verification;
/// the admission issuer must authenticate the presentation before signing a grant.
pub fn member_id(pseudonym: &[u8; 48]) -> String {
    digest(pseudonym)
}

pub fn device_authorization_bytes(value: &DeviceAuthorization) -> Result<Vec<u8>, Error> {
    if value.version != 1
        || value.issued_at == 0
        || value.issued_at >= value.expires_at
        || value.expires_at > MAX_INTEGER
        || !scope(&value.community_id)
    {
        return Err(Error::Admission);
    }
    decode::<32>(&value.member_id)?;
    let root = VerifyingKey::from_bytes(&decode::<32>(&value.root_public_key)?)
        .map_err(|_| Error::Admission)?;
    if root.is_weak() {
        return Err(Error::Admission);
    }
    let key = VerifyingKey::from_bytes(&decode::<32>(&value.device_public_key)?)
        .map_err(|_| Error::Admission)?;
    if key.is_weak() {
        return Err(Error::Admission);
    }
    serde_json::to_vec(&serde_json::json!([
        "cmsg.device.v1",
        value.community_id,
        value.member_id,
        value.root_public_key,
        value.device_public_key,
        value.issued_at,
        value.expires_at
    ]))
    .map_err(|_| Error::Admission)
}

pub fn verify_device_authorization(
    value: &DeviceAuthorization,
    grant: &AdmissionGrant,
    now: u64,
) -> Result<(), Error> {
    let bytes = device_authorization_bytes(value).map_err(|_| Error::Admission)?;
    if value.community_id != grant.community_id
        || value.member_id != grant.member_id
        || value.device_public_key != grant.chat_public_key
        || now < value.issued_at
        || now >= value.expires_at
    {
        return Err(Error::Admission);
    }
    signature(&value.root_public_key, &bytes, &value.signature).map_err(|_| Error::Admission)
}
