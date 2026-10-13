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
const ANCHOR: &[u8] = b"record-epoch-anchor:v1";
const OBJECT_PREFIX: &[u8] = b"cblc.record-witnesses.v2\0";
const HPKE_INFO: &[u8] = b"cblc.record-witness.v2\0";
const MAX_FRONTIERS: u32 = 1 << 20;
mod install;
mod prepare;
pub(super) use install::{existing_in, install_in};
pub(super) use prepare::{Inputs as EpochInputs, prepare_in};

const ANCESTRY_PREFIX: &[u8] = b"record-ancestry-latest:v1:";

// Attached to the current Frontier in the publication transaction. It can only move
// with that Frontier's verified linear CAS, never with a caller's version claim.
#[derive(Serialize, Deserialize)]
pub(super) struct Lineage {
    epoch: u64,
    leaf: czkp::record::Leaf,
    index: u32,
    path: Vec<[u8; 32]>,
    pub(super) consumed: bool,
    requires_descendant: bool,
}
impl Lineage {
    pub(super) fn required_inbox(&self) -> [u8; 32] {
        self.leaf.required_inbox
    }
}

// Small immutable authority header, installed with the common object and all
// owner paths. Accepted updates never scan/decode the entire community object.
#[derive(Serialize, Deserialize)]
struct PublishedAnchor {
    descriptor: czkp::record::Epoch,
    period_seconds: u64,
    frozen_at: u64,
    configuration: Vec<u8>,
    extension_configuration: Vec<u8>,
}

/// Project only the actual atomic publication under the caller's already
/// checked configuration transaction. Missing halves or corrupt bytes refuse;
/// no supplied descriptor can replace the durable owner publication.
pub(super) fn public_descriptor(
    tx: &mut Transaction<'_>,
    community: &[u8; 32],
    policy_epoch: u64,
    proof_scope: &AccountProofScope,
    configuration: &[u8],
    extension_configuration: &[u8],
) -> Result<Option<czkp::record::Epoch>, Error> {
    let publication: Option<RecordEpochPublication> = tx.get(PUBLISHED)?;
    let anchor: Option<PublishedAnchor> = tx.get(ANCHOR)?;
    let (publication, anchor) = match (publication, anchor) {
        (None, None) => return Ok(None),
        (Some(publication), Some(anchor)) => (publication, anchor),
        _ => return Err(Error::Storage),
    };
    if publication.descriptor != anchor.descriptor
        || anchor.frozen_at < anchor.descriptor.starts_at
        || anchor.frozen_at >= anchor.descriptor.expires_at
        || anchor.descriptor.leaf_count > MAX_FRONTIERS
    {
        return Err(Error::Storage);
    }
    tuning::check_epoch_config_in(tx, &anchor.configuration, configuration)?;
    if anchor.extension_configuration != extension_configuration
        || anchor.descriptor.policy_epoch == 0
        || anchor.descriptor.policy_epoch > policy_epoch
        || &anchor.descriptor.proof_scope != proof_scope
    {
        return Err(Error::PolicyMismatch);
    }
    anchor
        .descriptor
        .validate(community, anchor.period_seconds)?;
    publication
        .descriptor
        .check_object(&publication.object)
        .map_err(|_| Error::Storage)?;
    Ok(Some(publication.descriptor))
}

pub(super) fn current_descriptor(
    tx: &mut Transaction<'_>,
    community: &[u8; 32],
    proof_scope: &AccountProofScope,
    configuration: &[u8],
    extension_configuration: &[u8],
) -> Result<czkp::record::Epoch, Error> {
    let anchor: PublishedAnchor = tx.get(ANCHOR)?.ok_or(Error::Admission)?;
    public_descriptor(
        tx,
        community,
        anchor.descriptor.policy_epoch,
        proof_scope,
        configuration,
        extension_configuration,
    )?
    .ok_or(Error::Admission)
}

fn ancestry_key(owner: &[u8; 32]) -> Vec<u8> {
    [ANCESTRY_PREFIX, owner.as_slice()].concat()
}

pub(super) fn require_issuer(
    tx: &mut Transaction<'_>,
    owner: &[u8; 32],
    now: u64,
) -> Result<(), Error> {
    if tx
        .get::<Frontier>(&key(1, &[owner]))?
        .is_some_and(|f| f.record_ancestry.is_some())
    {
        let published: PublishedAnchor = tx.get(ANCHOR)?.ok_or(Error::Storage)?;
        if now < published.descriptor.expires_at {
            return Err(Error::UnsupportedCapability);
        }
    }
    Ok(())
}

pub(super) fn retain(
    tx: &mut Transaction<'_>,
    owner: &[u8; 32],
    certificate: Option<&crate::extensions::EpochAncestryCertificate>,
) -> Result<(), Error> {
    match certificate {
        Some(certificate) => tx.put(&ancestry_key(owner), certificate),
        None => tx.delete(&ancestry_key(owner)),
    }
}

// Recovery is part of the same authenticated exact-retry transaction. It never
// consults the current epoch and cannot turn an old acceptance into new evidence.
pub(super) fn recover(
    tx: &mut Transaction<'_>,
    accepted: &AccountAcceptance,
    issuer: Option<&cssr::certificate::CertificateIssuer>,
    record_key: &[u8; 32],
) -> Result<Option<crate::extensions::EpochAncestryCertificate>, Error> {
    let Some(issuer) = issuer else {
        return Ok(None);
    };
    let certificate: Option<crate::extensions::EpochAncestryCertificate> =
        tx.get(&ancestry_key(&accepted.statement.owner))?;
    if let Some(certificate) = &certificate {
        if certificate.community != accepted.statement.community
            || certificate.owner != accepted.statement.owner
            || certificate.state != accepted.statement.next_state
            || certificate.version != accepted.statement.next_version
            || certificate.proof_scope != accepted.proof_scope
            || certificate.issued_at != accepted.accepted_at
        {
            return Err(Error::Storage);
        }
        certificate
            .verify(&issuer.public_key())
            .map_err(|_| Error::Storage)?;
        if certificate.record.leaf.owner != certificate.owner
            || certificate.record.leaf.version > certificate.version
        {
            return Err(Error::Storage);
        }
        let leaf = certificate
            .record
            .leaf
            .commitment(&certificate.community, certificate.epoch)?;
        czkp::record::verify_certificate(
            record_key,
            &certificate.community,
            certificate.epoch,
            &leaf,
            &certificate.record.signature,
        )
        .map_err(|_| Error::Storage)?;
    }
    Ok(certificate)
}

// Called only after full proof verification, mutable CAS checks and complete
// inbox consumption, with the lineage inherited from the actual predecessor.
pub(super) fn certify(
    tx: &mut Transaction<'_>,
    accepted: &AccountAcceptance,
    lineage: &Lineage,
    configuration: &[u8],
    extensions: &Extensions,
    issuer: &cssr::certificate::CertificateIssuer,
    record_issuer: &cssr::certificate::RecordIssuer,
) -> Result<Option<crate::extensions::EpochAncestryCertificate>, Error> {
    let published: PublishedAnchor = tx.get(ANCHOR)?.ok_or(Error::Storage)?;
    let descriptor = &published.descriptor;
    if accepted.accepted_at >= descriptor.expires_at {
        return Ok(None);
    }
    tuning::check_epoch_config_in(tx, &published.configuration, configuration)?;
    if descriptor.community != accepted.statement.community
        || published.extension_configuration != extensions.config
        || descriptor.proof_scope != accepted.proof_scope
        || published.frozen_at > accepted.accepted_at
        || lineage.epoch != descriptor.epoch
        || !lineage.consumed
        || descriptor.issuer_key != record_issuer.public_key()
        || extensions.artifact_binding.certificate_key != issuer.public_key()
    {
        return Err(Error::PolicyMismatch);
    }
    descriptor.validate(&accepted.statement.community, published.period_seconds)?;
    if published.frozen_at < descriptor.starts_at
        || published.frozen_at >= descriptor.expires_at
        || descriptor.leaf_count > MAX_FRONTIERS
        || lineage.leaf.owner != accepted.statement.owner
        || lineage.index >= descriptor.leaf_count
        || lineage.path.len() != descriptor.depth() as usize
    {
        return Err(Error::Storage);
    }
    let leaf = lineage
        .leaf
        .commitment(&descriptor.community, descriptor.epoch)?;
    // This exact owner leaf/path was installed atomically from the real snapshot.
    // Keep the check O(log n); neither a caller nor a version comparison supplies it.
    if !rs_merkle::MerkleProof::<czkp::record::EpochTree>::new(lineage.path.clone()).verify(
        descriptor.root,
        &[lineage.index as usize],
        &[leaf],
        (descriptor.leaf_count as usize).max(2).next_power_of_two(),
    ) {
        return Err(Error::Storage);
    }
    // Keep the frozen public leaf stable unless the frozen required inbox forced
    // a descendant. Ordinary later updates never make record leaves track activity.
    let record_leaf = if lineage.requires_descendant {
        let applied = crate::extensions::applied(tx, &accepted.statement.owner)?;
        if applied != crate::extensions::inbox(tx, &accepted.statement.owner)? {
            return Err(Error::Admission);
        }
        let mut blinding = [0; 32];
        getrandom::fill(&mut blinding).map_err(|_| Error::CryptoProvider)?;
        czkp::record::Leaf {
            owner: accepted.statement.owner,
            version: accepted.statement.next_version,
            state: accepted.statement.next_state,
            required_inbox: applied.root,
                role: 0,
            blinding,
        }
    } else {
        lineage.leaf.clone()
    };
    let record_commitment = record_leaf.commitment(&descriptor.community, descriptor.epoch)?;
    let record = czkp::record::SignedLeaf {
        leaf: record_leaf,
        signature: record_issuer
            .issue(&descriptor.community, descriptor.epoch, &record_commitment)
            .map_err(|_| Error::CryptoProvider)?
            .to_vec(),
    };
    let mut certificate = crate::extensions::EpochAncestryCertificate {
        community: descriptor.community,
        owner: accepted.statement.owner,
        epoch: descriptor.epoch,
        root: descriptor.root,
        frozen_leaf: leaf,
        state: accepted.statement.next_state,
        version: accepted.statement.next_version,
        proof_scope: accepted.proof_scope.clone(),
        issued_at: accepted.accepted_at,
        signature: Vec::new(),
        record,
    };
    certificate.signature = issuer
        .sign(
            &certificate
                .body()
                .bytes()
                .map_err(|_| Error::CryptoProvider)?,
        )
        .to_vec();
    Ok(Some(certificate))
}

pub use crate::contracts::{RecipientRequest, recipient_bytes};

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
    issuer_key: [u8; 32],
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
    pub(super) fn encrypt(
        &self,
        issuer: &cssr::certificate::RecordIssuer,
    ) -> Result<RecordEpochPublication, Error> {
        let frozen = &self.0;
        if issuer.public_key() != frozen.issuer_key {
            return Err(Error::PolicyMismatch);
        }
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
        let tree = rs_merkle::MerkleTree::<czkp::record::EpochTree>::from_leaves(&leaves);
        let root = tree.root().ok_or(Error::Storage)?;
        let depth = padded.ilog2() as usize;
        let packet_bytes = 32 + 16 + 140 + 32 * depth + 64;
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
            purpose: czkp::record::Purpose::RecordEpochV3,
            community: frozen.community,
            policy_epoch: frozen.policy_epoch,
            epoch: frozen.epoch,
            starts_at: frozen.epoch * frozen.period_seconds,
            expires_at: (frozen.epoch + 1) * frozen.period_seconds,
            root,
            issuer_key: frozen.issuer_key,
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
            let mut plaintext = Zeroizing::new(Vec::with_capacity(140 + depth * 32 + 64));
            plaintext.extend_from_slice(&frontier.leaf.owner);
            plaintext.extend_from_slice(&frontier.leaf.version.to_be_bytes());
            plaintext.extend_from_slice(&frontier.leaf.state);
            plaintext.extend_from_slice(&frontier.leaf.required_inbox);
            plaintext.extend_from_slice(&frontier.leaf.blinding);
            plaintext.extend_from_slice(&(index as u32).to_be_bytes());
            for sibling in path.proof_hashes() {
                plaintext.extend_from_slice(sibling);
            }
            plaintext.extend_from_slice(
                &issuer
                    .issue(&frozen.community, frozen.epoch, &leaves[index])
                    .map_err(|_| Error::CryptoProvider)?,
            );
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
    .map_err(|_| Error::InvalidInput)
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Prepare the common object without mutating member authority, then install
    /// it with every lineage in one checked transaction. A racing member update
    /// invalidates preparation, never blocks member accounting. Concurrent or
    /// repeated successful publications return the original object unchanged.
    pub fn publish_record_epoch(
        &mut self,
        policy_epoch: u64,
        period_seconds: u64,
        clock: impl Fn() -> u64,
    ) -> Result<RecordEpochPublication, Error> {
        if self.settlement.is_some() {
            return self.publish_daily_settlement(policy_epoch, period_seconds, clock);
        }
        let clock = observed_clock(self.observed_time.clone(), clock);
        let frozen = self.freeze_record_epoch(policy_epoch, period_seconds, &clock)?;
        let record_issuer = cssr::certificate::RecordIssuer::new(&self.operator.to_bytes());
        let published = frozen.encrypt(&record_issuer)?;
        let mut tx = self.connection.transaction()?;
        let now = clock();
        check_time(now, frozen.0.frozen_at.max(clock_floor(&mut tx)?))?;
        published.descriptor.check_time(now)?;
        super::settlement::legacy_fence(&mut tx)?;
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, self.extensions.as_ref())?;
        if let Some(prior) = tx.get::<RecordEpochPublication>(PUBLISHED)? {
            if prior.descriptor.epoch > published.descriptor.epoch {
                return Err(Error::Replay);
            }
            if prior.descriptor.epoch == published.descriptor.epoch {
                prior.descriptor.validate(&self.community, period_seconds)?;
                let anchor: PublishedAnchor = tx.get(ANCHOR)?.ok_or(Error::Storage)?;
                tuning::check_epoch_config_in(&mut tx, &anchor.configuration, &self.config)?;
                tuning::check_epoch_config_in(&mut tx, &frozen.0.configuration, &self.config)?;
                if prior.descriptor.policy_epoch == 0
                    || prior.descriptor.policy_epoch > policy_epoch
                    || prior.descriptor.proof_scope != frozen.0.proof_scope
                    || anchor.descriptor != prior.descriptor
                    || anchor.extension_configuration != frozen.0.extension_configuration
                {
                    return Err(Error::PolicyMismatch);
                }
                let digest: [u8; 32] = Sha256::digest(&prior.object).into();
                if prior.descriptor.download_digest != digest
                    || prior.descriptor.download_bytes != prior.object.len() as u64
                {
                    return Err(Error::Storage);
                }
                tx.rollback()?;
                let returned = clock();
                check_time(returned, now)?;
                prior.descriptor.check_time(returned)?;
                return Ok(prior);
            }
        }
        install::install_in(&mut tx, &frozen, &published, now)?;
        tx.commit_before(&CommitDeadline::new(
            &clock,
            now,
            published.descriptor.expires_at,
        ))?;
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
        let clock = observed_clock(self.observed_time.clone(), clock);
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
        tx.commit_before(&CommitDeadline::new(
            &clock,
            now,
            request
                .expires_at
                .min(grant.expires_at)
                .min(authorization.expires_at),
        ))
    }

    /// Prepare a read-only candidate snapshot of all current account frontiers.
    /// It becomes a durable freeze only when publish_record_epoch atomically
    /// validates and installs it with the common object and every owner lineage.
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
        if self.settlement.is_some() {
            return Err(Error::UnsupportedCapability);
        }
        let clock = observed_clock(self.observed_time.clone(), clock);
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
        extensions.verifier.require_record_epoch()?;
        let mut tx = self.connection.transaction()?;
        check_time(now, clock_floor(&mut tx)?)?;
        super::settlement::legacy_fence(&mut tx)?;
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, Some(extensions))?;
        if let Some(prior) = tx.get::<FrozenEpochState>(FROZEN)? {
            if prior.epoch > epoch {
                return Err(Error::ClockRollback);
            }
            if prior.epoch == epoch {
                tuning::check_epoch_config_in(&mut tx, &prior.configuration, &self.config)?;
                if prior.community != self.community
                    || prior.policy_epoch == 0
                    || prior.policy_epoch > policy_epoch
                    || prior.period_seconds != period_seconds
                    || prior.extension_configuration != extensions.config
                {
                    return Err(Error::PolicyMismatch);
                }
                tx.rollback()?;
                let returned = clock();
                check_time(returned, now)?;
                if returned / period_seconds != epoch {
                    return Err(Error::Expired);
                }
                return Ok(FrozenEpoch(prior));
            }
        }
        let frozen = prepare::prepare_in(
            &mut tx,
            &prepare::Inputs {
                community: self.community,
                issuer_key: self.operator.verifying_key().to_bytes(),
                policy_epoch,
                epoch,
                period_seconds,
                now,
                configuration: &self.config,
                extension_configuration: &extensions.config,
                proof_scope: &extensions.verifier.scope(),
            },
            &clock,
        )?;
        let completed = frozen.0.frozen_at;
        tx.rollback()?;
        let returned = clock();
        check_time(returned, completed)?;
        if returned / period_seconds != epoch {
            return Err(Error::Expired);
        }
        Ok(frozen)
    }
}

#[cfg(test)]
#[path = "../../tests/internal/record_epoch.rs"]
mod tests;
