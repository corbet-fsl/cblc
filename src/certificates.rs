//! Canonical accepted-state and epoch-ancestry certificate transcripts, and their
//! verification. cblc is the single owner of these signed formats: the issuer
//! (cssr) signs the bytes encoded here and every holder verifies through this
//! module. The accepted-state layout is also consumed by the Noir deposit
//! relation and must not change.
use crate::{Error, accounting::AccountAcceptance};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

const MAX_INTEGER: u64 = (1 << 53) - 1;
const STATE_DOMAIN: &[u8] = b"cssr.accepted-state.v1\0";
const ANCESTRY_DOMAIN: &[u8] = b"cblc.epoch-ancestry.v1\0";

/// Domain-separated certificate body. No opening or counterpart enters the issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedState {
    /// Community hash.
    pub community: [u8; 32],
    /// Community-scoped opaque account owner.
    pub owner: [u8; 32],
    /// Accepted state commitment.
    pub state: [u8; 32],
    /// Digest of the pinned extension circuit manifest.
    pub scope: [u8; 32],
    /// Accepted version.
    pub version: u64,
    /// Issuer acceptance time, hidden inside anonymous deposit proofs.
    pub accepted_at: u64,
}

impl AcceptedState {
    /// The one mapping from an operator acceptance to its certificate body.
    pub fn from_acceptance(accepted: &AccountAcceptance) -> Self {
        Self {
            community: accepted.statement.community,
            owner: accepted.statement.owner,
            state: accepted.statement.next_state,
            scope: accepted.proof_scope.circuit_digest,
            version: accepted.statement.next_version,
            accepted_at: accepted.accepted_at,
        }
    }

    /// Fixed encoding also checked inside the Noir deposit relation.
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = STATE_DOMAIN.to_vec();
        for field in [self.community, self.owner, self.state, self.scope] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.accepted_at.to_be_bytes());
        bytes
    }

    /// Verify the issuer's canonical low-S P-256 signature over these bytes.
    pub fn verify(&self, key: &[u8; 64], signature: &[u8; 64]) -> Result<(), Error> {
        verify_bytes(key, &self.bytes(), signature)
    }
}

/// Private minimum-frontier ancestry statement, distinct from a state certificate.
/// This body alone is never evidence of ancestry or a public member record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochAncestryBody {
    /// Community hash.
    pub community: [u8; 32],
    /// Community-scoped account owner, hidden in the eventual record proof.
    pub owner: [u8; 32],
    /// Published epoch number.
    pub epoch: u64,
    /// Published epoch root.
    pub root: [u8; 32],
    /// Exact blinded frozen leaf commitment in that root.
    pub frozen_leaf: [u8; 32],
    /// Newly accepted descendant commitment.
    pub state: [u8; 32],
    /// Newly accepted version.
    pub version: u64,
    /// Original update circuit manifest digest.
    pub circuit_digest: [u8; 32],
    /// Original update verification-key digest.
    pub verifying_key_digest: [u8; 32],
    /// Acceptance time of this descendant, never refreshed on retry.
    pub issued_at: u64,
}

impl EpochAncestryBody {
    /// Canonical fixed-width transcript: domain, community, owner, epoch, root,
    /// frozen leaf, state, version, both proof-scope digests, issuance time, then
    /// the compact message form. Digests are opaque; callers check circuit encodings.
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        if self.epoch == 0
            || self.epoch > MAX_INTEGER
            || self.version > MAX_INTEGER
            || self.issued_at == 0
            || self.issued_at > MAX_INTEGER
            || [
                self.community,
                self.owner,
                self.root,
                self.frozen_leaf,
                self.state,
                self.circuit_digest,
                self.verifying_key_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(Error::InvalidInput);
        }
        let mut bytes = ANCESTRY_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.community);
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.root);
        bytes.extend_from_slice(&self.frozen_leaf);
        bytes.extend_from_slice(&self.state);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.circuit_digest);
        bytes.extend_from_slice(&self.verifying_key_digest);
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        Ok(czkp::compact::message(&bytes))
    }

    /// Verify the issuer's canonical low-S P-256 signature. The consumer must
    /// separately bind the expected epoch, owner and scope.
    pub fn verify(&self, key: &[u8; 64], signature: &[u8; 64]) -> Result<(), Error> {
        verify_bytes(key, &self.bytes()?, signature)
    }
}

fn verify_bytes(key: &[u8; 64], bytes: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
    let mut encoded = [4; 65];
    encoded[1..].copy_from_slice(key);
    let key = VerifyingKey::from_sec1_bytes(&encoded).map_err(|_| Error::Signature)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
    // A high-S alias has a valid mathematical signature but a second wire encoding.
    if signature.normalize_s().is_some() {
        return Err(Error::Signature);
    }
    key.verify(bytes, &signature).map_err(|_| Error::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    fn hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    fn sign(secret: u8, bytes: &[u8]) -> [u8; 64] {
        let key = SigningKey::from_slice(&[secret; 32]).unwrap();
        let signature: Signature = key.sign(bytes);
        signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into()
    }

    fn public(secret: u8) -> [u8; 64] {
        let key = SigningKey::from_slice(&[secret; 32]).unwrap();
        key.verifying_key().to_encoded_point(false).as_bytes()[1..]
            .try_into()
            .unwrap()
    }

    fn state() -> AcceptedState {
        AcceptedState {
            community: [1; 32],
            owner: [2; 32],
            state: [3; 32],
            scope: [4; 32],
            version: 7,
            accepted_at: 120,
        }
    }

    // cssr's tests sign exactly this transcript with issuer key [3; 32] and pin
    // this public key and signature. Verifying them here, with this encoder,
    // detects any divergence between the signer's input and the verifier.
    const GOLDEN_TRANSCRIPT: &str = "637373722e61636365707465642d73746174652e763100010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040400000000000000070000000000000078";
    const GOLDEN_PUBLIC_KEY: &str = "591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0";
    const GOLDEN_SIGNATURE: &str = "902f3030e007662ec00bdb101b6d1205c1d4c461816911db73e1b5d5235e1ed50f5f13410b15d71e59e5eafd6530be144df21ac9729aadbd05625edb52a826bc";

    #[test]
    fn the_signer_golden_vector_verifies_with_this_encoder() {
        assert_eq!(state().bytes(), hex(GOLDEN_TRANSCRIPT));
        let key: [u8; 64] = hex(GOLDEN_PUBLIC_KEY).try_into().unwrap();
        let signature: [u8; 64] = hex(GOLDEN_SIGNATURE).try_into().unwrap();
        state().verify(&key, &signature).unwrap();
        assert_eq!(key, public(3));
        assert_eq!(signature, sign(3, &state().bytes()));
    }

    #[test]
    fn accepted_state_binds_every_field_and_the_key() {
        let signature = sign(3, &state().bytes());
        let key = public(3);
        for field in 0..6 {
            let mut changed = state();
            match field {
                0 => changed.community[0] ^= 1,
                1 => changed.owner[0] ^= 1,
                2 => changed.state[0] ^= 1,
                3 => changed.scope[0] ^= 1,
                4 => changed.version += 1,
                _ => changed.accepted_at += 1,
            }
            assert!(changed.verify(&key, &signature).is_err());
        }
        assert!(state().verify(&public(4), &signature).is_err());
        assert!(state().verify(&[0; 64], &signature).is_err());
        assert!(state().verify(&key, &[0; 64]).is_err());
        let canonical = Signature::from_slice(&signature).unwrap();
        let (r, s) = canonical.split_scalars();
        let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
        assert!(high.normalize_s().is_some());
        assert!(state().verify(&key, &high.to_bytes().into()).is_err());
    }

    fn ancestry() -> EpochAncestryBody {
        EpochAncestryBody {
            community: [1; 32],
            owner: [2; 32],
            epoch: 3,
            root: [4; 32],
            frozen_leaf: [5; 32],
            state: [6; 32],
            version: 7,
            circuit_digest: [8; 32],
            verifying_key_digest: [9; 32],
            issued_at: 10,
        }
    }

    #[test]
    fn ancestry_transcript_vector_and_every_field_are_bound() {
        let body = ancestry();
        let raw = hex(concat!(
            "63626c632e65706f63682d616e6365737472792e763100",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "0000000000000003",
            "0404040404040404040404040404040404040404040404040404040404040404",
            "0505050505050505050505050505050505050505050505050505050505050505",
            "0606060606060606060606060606060606060606060606060606060606060606",
            "0000000000000007",
            "0808080808080808080808080808080808080808080808080808080808080808",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "000000000000000a",
        ));
        assert_eq!(body.bytes().unwrap(), czkp::compact::message(&raw));
        let signature = sign(3, &body.bytes().unwrap());
        body.verify(&public(3), &signature).unwrap();
        for field in 0..10 {
            let mut changed = ancestry();
            match field {
                0 => changed.community[0] ^= 1,
                1 => changed.owner[0] ^= 1,
                2 => changed.epoch += 1,
                3 => changed.root[0] ^= 1,
                4 => changed.frozen_leaf[0] ^= 1,
                5 => changed.state[0] ^= 1,
                6 => changed.version += 1,
                7 => changed.circuit_digest[0] ^= 1,
                8 => changed.verifying_key_digest[0] ^= 1,
                _ => changed.issued_at += 1,
            }
            assert!(changed.verify(&public(3), &signature).is_err());
        }
        // A state certificate signature is never ancestry evidence.
        let accepted = AcceptedState {
            community: body.community,
            owner: body.owner,
            state: body.state,
            scope: body.circuit_digest,
            version: body.version,
            accepted_at: body.issued_at,
        };
        let confused = sign(3, &accepted.bytes());
        assert!(body.verify(&public(3), &confused).is_err());
        assert!(accepted.verify(&public(3), &signature).is_err());
    }

    #[test]
    fn malformed_ancestry_bounds_cannot_be_encoded() {
        let max = (1 << 53) - 1;
        for field in 0..12 {
            let mut body = ancestry();
            match field {
                0 => body.community = [0; 32],
                1 => body.owner = [0; 32],
                2 => body.root = [0; 32],
                3 => body.frozen_leaf = [0; 32],
                4 => body.state = [0; 32],
                5 => body.circuit_digest = [0; 32],
                6 => body.verifying_key_digest = [0; 32],
                7 => body.epoch = 0,
                8 => body.epoch = 1 << 53,
                9 => body.version = 1 << 53,
                10 => body.issued_at = 0,
                _ => body.issued_at = 1 << 53,
            }
            assert!(body.bytes().is_err());
            assert!(body.verify(&public(3), &[1; 64]).is_err());
        }
        let mut boundary = ancestry();
        boundary.epoch = max;
        boundary.version = 0;
        boundary.issued_at = max;
        let signature = sign(3, &boundary.bytes().unwrap());
        boundary.verify(&public(3), &signature).unwrap();
    }
}
