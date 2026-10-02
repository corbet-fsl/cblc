//! Actual account recipient registration and atomic common epoch frontier freeze.
//! The issuer knows its own frontier map; nothing here is a Forum member lookup.
use super::*;
use hpke::{Deserializable, Serializable};
use rand::seq::SliceRandom;
use rand_core::SeedableRng;
use zeroize::Zeroizing;

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

const RECIPIENT_PREFIX: &[u8] = b"record-recipient:v1:";
const FROZEN: &[u8] = b"record-epoch-frozen:v1";
const PUBLISHED: &[u8] = b"record-epoch-published:v1";
const OBJECT_PREFIX: &[u8] = b"cblc.record-witnesses.v1\0";
const HPKE_INFO: &[u8] = b"cblc.record-witness.v1\0";
const MAX_FRONTIERS: u32 = 100_000;

#[cfg(test)]
#[path = "../../tests/internal/record_epoch.rs"]
mod tests;

/// The existing admitted account's device signs its common-root-derived recipient
/// key. This is an account enrollment operation, never a listing/contact request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientRequest {
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub recipient_key: [u8; 32],
    pub chat_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// Original device signature transcript, binding every recipient request field.
pub fn recipient_bytes(request: &RecipientRequest) -> Result<Vec<u8>, Error> {
    if request.recipient_key == [0; 32]
        || request.issued_at == 0
        || request.issued_at >= request.expires_at
        || request.expires_at > MAX_INTEGER
    {
        return Err(Error::InvalidInput);
    }
    decode::<32>(&request.chat_public_key)?;
    serde_json::to_vec(&serde_json::json!([
        "cblc.record-recipient.v1",
        request.community,
        request.owner,
        request.recipient_key,
        request.chat_public_key,
        request.issued_at,
        request.expires_at
    ]))
    .map_err(|_| Error::InvalidInput)
}

fn recipient_key(owner: &[u8; 32]) -> Vec<u8> {
    [RECIPIENT_PREFIX, owner.as_slice()].concat()
}

// Never exported to a client or a relying service. All stored fields come from
// the same actual issuer transaction, not from a proposed member record.
#[derive(Serialize, Deserialize)]
struct FrozenFrontier {
    recipient_key: [u8; 32],
    leaf: czkp::record::Leaf,
}

#[derive(Serialize, Deserialize)]
struct FrozenEpochState {
    community: [u8; 32],
    policy_epoch: u64,
    epoch: u64,
    period_seconds: u64,
    frozen_at: u64,
    configuration: Vec<u8>,
    extension_configuration: Vec<u8>,
    proof_scope: AccountProofScope,
    frontiers: Vec<FrozenFrontier>,
}

/// Opaque issuer snapshot for the common HPKE object builder. Not a verified
/// member record; no plaintext serializer, Debug or frontier getter is public.
pub struct FrozenEpoch(FrozenEpochState);

/// One common ciphertext object and its descriptor. Neither is authenticated
/// until the original Policy/Beacon signed publication binds these exact bytes.
#[derive(Clone, Serialize, Deserialize)]
pub struct RecordEpochPublication {
    descriptor: czkp::record::Epoch,
    object: Vec<u8>,
}
impl RecordEpochPublication {
    pub fn descriptor(&self) -> &czkp::record::Epoch {
        &self.descriptor
    }
    pub fn common_object(&self) -> &[u8] {
        &self.object
    }
}

impl FrozenEpoch {
    fn encrypt(&self) -> Result<RecordEpochPublication, Error> {
        let frozen = &self.0;
        let count = frozen.frontiers.len();
        let padded = count
            .max(2)
            .checked_next_power_of_two()
            .ok_or(Error::Capacity)?;
        let mut leaves = frozen
            .frontiers
            .iter()
            .map(|f| f.leaf.commitment(&frozen.community, frozen.epoch))
            .collect::<Result<Vec<_>, _>>()?;
        leaves.resize(padded, [0; 32]);
        let tree = rs_merkle::MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&leaves);
        let root = tree.root().ok_or(Error::Storage)?;
        let depth = padded.ilog2() as usize;
        let packet_bytes = 32 + 16 + 140 + 32 * depth;
        let object_bytes = OBJECT_PREFIX
            .len()
            .checked_add(8)
            .and_then(|header| {
                packet_bytes
                    .checked_mul(count)
                    .and_then(|packets| header.checked_add(packets))
            })
            .ok_or(Error::Capacity)?;
        if object_bytes as u64 > czkp::record::MAX_DOWNLOAD_BYTES {
            return Err(Error::Capacity);
        }
        let mut descriptor = czkp::record::Epoch {
            purpose: czkp::record::Purpose::RecordEpochV1,
            community: frozen.community,
            policy_epoch: frozen.policy_epoch,
            epoch: frozen.epoch,
            starts_at: frozen.epoch * frozen.period_seconds,
            expires_at: (frozen.epoch + 1) * frozen.period_seconds,
            root,
            proof_scope: frozen.proof_scope.clone(),
            leaf_count: count as u32,
            download_digest: [0; 32],
            download_bytes: object_bytes as u64,
        };
        let aad = packet_aad(&descriptor)?;
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::CryptoProvider)?;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
        let mut packets = Vec::with_capacity(count);
        for (index, frontier) in frozen.frontiers.iter().enumerate() {
            let path = tree.proof(&[index]);
            if path.proof_hashes().len() != depth {
                return Err(Error::Storage);
            }
            // Fixed width within the epoch: no clear owner, variable integer
            // length, recipient label, or per-member download path.
            let mut plaintext = Zeroizing::new(Vec::with_capacity(140 + depth * 32));
            plaintext.extend_from_slice(&frontier.leaf.owner);
            plaintext.extend_from_slice(&frontier.leaf.version.to_be_bytes());
            plaintext.extend_from_slice(&frontier.leaf.state);
            plaintext.extend_from_slice(&frontier.leaf.required_inbox);
            plaintext.extend_from_slice(&frontier.leaf.blinding);
            plaintext.extend_from_slice(&(index as u32).to_be_bytes());
            for sibling in path.proof_hashes() {
                plaintext.extend_from_slice(sibling);
            }
            let key = <Kem as hpke::Kem>::PublicKey::from_bytes(&frontier.recipient_key)
                .map_err(|_| Error::InvalidInput)?;
            // Base confidentiality is authenticated by the original signed
            // descriptor's digest over the WHOLE object, not an unsigned packet.
            let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
                &hpke::OpModeS::Base,
                &key,
                HPKE_INFO,
                &plaintext,
                &aad,
                &mut rng,
            )
            .map_err(|_| Error::CryptoProvider)?;
            let packet = [enc.to_bytes().as_slice(), ciphertext.as_slice()].concat();
            if packet.len() != packet_bytes {
                return Err(Error::CryptoProvider);
            }
            packets.push(packet);
        }
        packets.shuffle(&mut rng);
        let mut object = Vec::with_capacity(object_bytes);
        object.extend_from_slice(OBJECT_PREFIX);
        object.extend_from_slice(&(count as u32).to_be_bytes());
        object.extend_from_slice(&(packet_bytes as u32).to_be_bytes());
        for packet in packets {
            object.extend_from_slice(&packet);
        }
        descriptor.download_digest = Sha256::digest(&object).into();
        descriptor.validate(&frozen.community, frozen.period_seconds)?;
        Ok(RecordEpochPublication { descriptor, object })
    }
}

fn packet_aad(epoch: &czkp::record::Epoch) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&serde_json::json!([
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
    .map_err(|_| Error::InvalidInput)
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Scheduled publication only. Persist the exact ciphertext bytes once;
    /// retries and concurrent publishers return the original object unchanged.
    pub fn publish_record_epoch(
        &mut self,
        policy_epoch: u64,
        period_seconds: u64,
        clock: impl Fn() -> u64,
    ) -> Result<RecordEpochPublication, Error> {
        let frozen = self.freeze_record_epoch(policy_epoch, period_seconds, &clock)?;
        let published = frozen.encrypt()?;
        let mut tx = self.connection.transaction()?;
        let now = clock();
        check_time(now, frozen.0.frozen_at.max(clock_floor(&mut tx)?))?;
        published.descriptor.check_time(now)?;
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, self.extensions.as_ref())?;
        let current: FrozenEpochState = tx.get(FROZEN)?.ok_or(Error::Storage)?;
        if current.epoch != frozen.0.epoch
            || current.policy_epoch != frozen.0.policy_epoch
            || current.period_seconds != frozen.0.period_seconds
            || current.configuration != frozen.0.configuration
            || current.extension_configuration != frozen.0.extension_configuration
        {
            return Err(Error::Replay);
        }
        if let Some(prior) = tx.get::<RecordEpochPublication>(PUBLISHED)? {
            if prior.descriptor.epoch > published.descriptor.epoch {
                return Err(Error::Replay);
            }
            if prior.descriptor.epoch == published.descriptor.epoch {
                let mut expected = published.descriptor.clone();
                expected.download_digest = prior.descriptor.download_digest;
                if prior.descriptor != expected {
                    return Err(Error::Replay);
                }
                let digest: [u8; 32] = Sha256::digest(&prior.object).into();
                if prior.descriptor.download_digest != digest
                    || prior.descriptor.download_bytes != prior.object.len() as u64
                {
                    return Err(Error::Storage);
                }
                tx.rollback()?;
                return Ok(prior);
            }
        }
        tx.put(PUBLISHED, &published)?;
        advance_clock(&mut tx, now)?;
        tx.commit()?;
        Ok(published)
    }
    /// Register once, or idempotently repeat the SAME member-wide recipient.
    /// A different key needs an explicit future custody migration; device loss
    /// must not silently rotate it. All equal passkeys derive the same key.
    pub fn register_record_recipient(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &RecipientRequest,
        clock: impl Fn() -> u64,
    ) -> Result<(), Error> {
        let bytes = recipient_bytes(request)?;
        if request.community != self.community
            || decode::<32>(&grant.member_id)? != request.owner
            || request.chat_public_key != grant.chat_public_key
        {
            return Err(Error::Admission);
        }
        if request.expires_at - request.issued_at > self.policy.max_authorization_seconds {
            return Err(Error::Expired);
        }
        let before = clock();
        check_time(before, 0)?;
        verify_admission(grant, &self.trust, before)?;
        verify_device_authorization(authorization, grant, before)?;
        signature(&request.chat_public_key, &bytes, &request.signature)?;
        let mut tx = self.connection.transaction()?;
        let now = clock();
        check_time(now, before.max(clock_floor(&mut tx)?))?;
        check_config(&mut tx, &self.config)?;
        verify_admission(grant, &self.trust, now)?;
        verify_device_authorization(authorization, grant, now)?;
        if now < request.issued_at || now >= request.expires_at {
            return Err(Error::Expired);
        }
        check_root(
            &mut tx,
            &request.owner,
            &decode::<32>(&authorization.root_public_key)?,
        )?;
        // An accepted account MUST already exist. check_root alone permits a
        // fresh genesis, which cannot authorize a recipient registry entry.
        tx.get::<Frontier>(&key(1, &[&request.owner]))?
            .ok_or(Error::Admission)?;
        let key = recipient_key(&request.owner);
        if let Some(old) = tx.get::<[u8; 32]>(&key)? {
            if old != request.recipient_key {
                return Err(Error::Replay);
            }
        } else {
            tx.put(&key, &request.recipient_key)?;
        }
        advance_clock(&mut tx, now)?;
        tx.commit()
    }

    /// Freeze all current account frontiers together once per configured epoch.
    /// Trusted scheduled publication supplies current Policy epoch and original
    /// Rulebook duration. Member service requests do not expose this method.
    /// Missing recipient registration, malformed storage or capacity overflow
    /// refuses the ENTIRE freeze; no silently omitted member can produce a root.
    pub fn freeze_record_epoch(
        &mut self,
        policy_epoch: u64,
        period_seconds: u64,
        clock: impl Fn() -> u64,
    ) -> Result<FrozenEpoch, Error> {
        let now = clock();
        check_time(now, 0)?;
        if policy_epoch == 0
            || policy_epoch > MAX_INTEGER
            || period_seconds == 0
            || period_seconds > MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        let epoch = now / period_seconds;
        if epoch == 0
            || (epoch + 1)
                .checked_mul(period_seconds)
                .is_none_or(|end| end > MAX_INTEGER)
        {
            return Err(Error::InvalidInput);
        }
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let mut tx = self.connection.transaction()?;
        check_time(now, clock_floor(&mut tx)?)?;
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, Some(extensions))?;
        if let Some(prior) = tx.get::<FrozenEpochState>(FROZEN)? {
            if prior.epoch > epoch {
                return Err(Error::ClockRollback);
            }
            if prior.epoch == epoch {
                if prior.community != self.community
                    || prior.policy_epoch != policy_epoch
                    || prior.period_seconds != period_seconds
                    || prior.configuration != self.config
                    || prior.extension_configuration != extensions.config
                {
                    return Err(Error::PolicyMismatch);
                }
                tx.rollback()?;
                return Ok(FrozenEpoch(prior));
            }
        }
        let rows: Vec<(Vec<u8>, Frontier)> = tx.current_range(&[1], &[2], MAX_FRONTIERS + 1)?;
        if rows.is_empty() || rows.len() > MAX_FRONTIERS as usize {
            return Err(Error::Capacity);
        }
        let mut frontiers = Vec::with_capacity(rows.len());
        for (stored_key, frontier) in rows {
            if stored_key.len() != 41 || stored_key[1..9] != 32_u64.to_be_bytes() {
                return Err(Error::Storage);
            }
            let owner: [u8; 32] = stored_key[9..].try_into().map_err(|_| Error::Storage)?;
            let recipient = tx
                .get::<[u8; 32]>(&recipient_key(&owner))?
                .ok_or(Error::Admission)?;
            if recipient == [0; 32] {
                return Err(Error::Storage);
            }
            let mut blinding = [0; 32];
            getrandom::fill(&mut blinding).map_err(|_| Error::CryptoProvider)?;
            let leaf = czkp::record::Leaf {
                owner,
                version: frontier.version,
                state: frontier.state,
                required_inbox: extensions::inbox(&mut tx, &owner)?.root,
                blinding,
            };
            leaf.commitment(&self.community, epoch)?;
            frontiers.push(FrozenFrontier {
                recipient_key: recipient,
                leaf,
            });
        }
        let completed = clock();
        check_time(completed, now)?;
        if completed / period_seconds != epoch {
            return Err(Error::Expired);
        }
        let frozen = FrozenEpochState {
            community: self.community,
            policy_epoch,
            epoch,
            period_seconds,
            frozen_at: completed,
            configuration: self.config.clone(),
            extension_configuration: extensions.config.clone(),
            proof_scope: extensions.verifier.scope(),
            frontiers,
        };
        tx.put(FROZEN, &frozen)?;
        advance_clock(&mut tx, completed)?;
        tx.commit()?;
        Ok(FrozenEpoch(frozen))
    }
}
