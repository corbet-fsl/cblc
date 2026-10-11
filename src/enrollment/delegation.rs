use super::ACCOUNT_HASH_SCHEME;
use crate::{Error, admission::*};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER as HEX};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Original delegation wire object. Its device signature authorizes the P-256
/// coordinate; subsequent accounting signatures prove possession of that key.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountingDelegation {
    /// Original delegation protocol version, exactly one.
    pub version: u32,
    /// Original account hash scheme, never selected by a verifier callback.
    pub hash_scheme: String,
    /// Current Policy's signed eligibility envelope.
    pub admission: AdmissionGrant,
    /// Member root's authorization for the signing device.
    pub authorization: DeviceAuthorization,
    /// Canonical lowercase P-256 X || Y hex, without a SEC1 prefix.
    pub account_public_key: String,
    /// Canonical lowercase bytes32 secret-commitment hex.
    pub state_secret_commitment: String,
    /// Device-selected start of the bounded delegation interval.
    pub issued_at: u64,
    /// Exclusive end, no later than either authenticated authority's end.
    pub expires_at: u64,
    /// Canonical base64url strict Ed25519 device signature.
    pub signature: String,
}
impl std::fmt::Debug for AccountingDelegation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountingDelegation([redacted])")
    }
}

/// Independently selected current Policy expectations. The host retains its
/// real Policy, member, session and device leases through storage/forwarding;
/// this cryptographic adapter does not infer those expectations from a grant.
pub struct ExpectedAdmission<'a> {
    /// Independently configured community, immutable digest and Policy ring.
    pub trust: &'a AdmissionTrust,
    /// Actual current admission epoch from the same Policy decision.
    pub policy_epoch: u64,
    /// Actual current authenticated global passport-policy digest.
    pub passport_policy_digest: &'a str,
}

/// One authenticated public delegation at the recorded check time. This is not
/// an enrollment root, a live role lease, or proof of a private wallet opening.
pub struct VerifiedDelegation {
    delegation: AccountingDelegation,
    digest: [u8; 32],
    checked_at: u64,
}
impl VerifiedDelegation {
    /// Exact complete authenticated wire input.
    pub fn delegation(&self) -> &AccountingDelegation {
        &self.delegation
    }
    /// Original purpose-separated transcript-and-signature digest.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Trusted time at which both current authority checks succeeded.
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    /// Exclusive original delegation bound, already within both authorities.
    pub fn valid_until(&self) -> u64 {
        self.delegation.expires_at
    }
}

fn hash(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    if value.len() != N * 2 {
        return Err(Error::Admission);
    }
    HEX.decode(value.as_bytes())
        .map_err(|_| Error::Admission)?
        .try_into()
        .map_err(|_| Error::Admission)
}

impl AccountingDelegation {
    fn bounded(&self) -> Result<(), Error> {
        if self.hash_scheme.len() > 128
            || self.admission.community_id.len() > 128
            || self.authorization.community_id.len() > 128
            || self.account_public_key.len() != 128
            || self.state_secret_commitment.len() != 64
            || (!self.signature.is_empty() && self.signature.len() != 86)
            || self.admission.signature.len() > 8192
        {
            return Err(Error::Admission);
        }
        for value in [
            &self.admission.issuer_key_id,
            &self.admission.member_id,
            &self.admission.chat_public_key,
            &self.admission.policy_digest,
            &self.admission.passport_policy_digest,
            &self.authorization.member_id,
            &self.authorization.root_public_key,
            &self.authorization.device_public_key,
        ] {
            if value.len() != 43 {
                return Err(Error::Admission);
            }
        }
        if self.admission.pseudonym.len() != 96 || self.authorization.signature.len() != 86 {
            return Err(Error::Admission);
        }
        Ok(())
    }

    /// Encode the original v1 ordered transcript, including complete wire
    /// hashes of the current signed grant and root device authorization.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        self.bounded()?;
        serde_json::to_vec(&serde_json::json!([
            "cmsg.accounting-delegation.v1",
            self.version,
            self.hash_scheme,
            self.admission.community_id,
            self.admission.member_id,
            self.authorization.device_public_key,
            self.account_public_key,
            self.state_secret_commitment,
            self.issued_at,
            self.expires_at,
            B64.encode(&hash(
                serde_json::to_vec(&self.admission).map_err(|_| Error::Admission)?
            )),
            B64.encode(&hash(
                serde_json::to_vec(&self.authorization).map_err(|_| Error::Admission)?
            )),
        ]))
        .map_err(|_| Error::Admission)
    }

    /// Digest includes the strict Ed25519 signature and complete transcript.
    /// A digest alone does not authenticate a delegation; call the verifier.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        let transcript = self.signing_bytes()?;
        let mut bytes = b"cmsg.accounting-delegation-digest.v1\0".to_vec();
        bytes.extend_from_slice(&(transcript.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&transcript);
        let signature = B64
            .decode(self.signature.as_bytes())
            .map_err(|_| Error::Admission)?;
        if signature.len() != 64 || B64.encode(&signature) != self.signature {
            return Err(Error::Admission);
        }
        bytes.extend_from_slice(&signature);
        Ok(hash(bytes))
    }
}

/// Authenticate the original device delegation under independently current
/// v3 Policy expectations, both now and when the device issued it. Historical
/// publication verification must use a separate authenticated-history boundary.
pub fn verify_delegation(
    d: &AccountingDelegation,
    expected: ExpectedAdmission<'_>,
    now: u64,
) -> Result<VerifiedDelegation, Error> {
    let digest = authenticate(d, expected, now)?;
    Ok(VerifiedDelegation {
        delegation: d.clone(),
        digest,
        checked_at: now,
    })
}

// Historical correspondence is private to reconstruction of the actual
// operator-authenticated original frozen slot. It is not current admission.
pub(super) struct HistoricalDelegation {
    pub(super) delegation: AccountingDelegation,
    pub(super) digest: [u8; 32],
}
pub(super) fn verify_historical(
    d: &AccountingDelegation,
    expected: ExpectedAdmission<'_>,
    original_cut: u64,
) -> Result<HistoricalDelegation, Error> {
    let digest = authenticate(d, expected, original_cut)?;
    Ok(HistoricalDelegation {
        delegation: d.clone(),
        digest,
    })
}

fn authenticate(
    d: &AccountingDelegation,
    expected: ExpectedAdmission<'_>,
    now: u64,
) -> Result<[u8; 32], Error> {
    d.bounded()?;
    if now == 0
        || now > czkp::MAX_INTEGER
        || d.issued_at == 0
        || d.version != 1
        || d.signature.len() != 86
        || d.hash_scheme != ACCOUNT_HASH_SCHEME
        || d.issued_at > now
        || now >= d.expires_at
        || d.issued_at >= d.expires_at
        || d.expires_at > czkp::MAX_INTEGER
        || d.expires_at > d.admission.expires_at
        || d.expires_at > d.authorization.expires_at
        || expected.policy_epoch == 0
        || d.admission.policy_epoch != expected.policy_epoch
        || d.admission.passport_policy_digest != expected.passport_policy_digest
    {
        return Err(Error::Admission);
    }
    let device =
        czkp::decode::<32>(&d.authorization.device_public_key).map_err(|_| Error::Admission)?;
    let coordinate = hex::<64>(&d.account_public_key)?;
    let mut point = [0; 65];
    point[0] = 4;
    point[1..].copy_from_slice(&coordinate);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| Error::Admission)?;
    hex::<32>(&d.state_secret_commitment)?;
    for at in [now, d.issued_at] {
        verify_admission(&d.admission, expected.trust, at)?;
        verify_device_authorization(&d.authorization, &d.admission, at)?;
    }
    let signature = B64
        .decode(d.signature.as_bytes())
        .map_err(|_| Error::Admission)?;
    if signature.len() != 64 || B64.encode(&signature) != d.signature {
        return Err(Error::Admission);
    }
    VerifyingKey::from_bytes(&device)
        .map_err(|_| Error::Admission)?
        .verify_strict(
            &d.signing_bytes()?,
            &Signature::from_slice(&signature).map_err(|_| Error::Admission)?,
        )
        .map_err(|_| Error::Admission)?;
    d.digest()
}
