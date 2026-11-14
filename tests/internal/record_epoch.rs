//! Actual maintained HPKE/tree interoperability and measured common-download cost.
//! Synthetic frontier values exercise the format; they are not admitted accounts.
use super::*;
use crate::accounting::AccountStatement;
use hpke::Kem as _;
use std::time::Instant;

fn material(index: u32) -> (<Kem as hpke::Kem>::PrivateKey, [u8; 32]) {
    let seed: [u8; 32] = Sha256::digest(index.to_be_bytes()).into();
    let (secret, public) = Kem::derive_keypair(&seed);
    (secret, public.to_bytes().as_slice().try_into().unwrap())
}

fn fixture(count: u32) -> FrozenEpoch {
    let mut frontiers = Vec::new();
    for index in 0..count {
        let mut state = [0; 32];
        state[31] = 1;
        frontiers.push(FrozenFrontier {
            recipient_key: material(index).1,
            leaf: czkp::record::Leaf {
                owner: Sha256::digest(index.to_be_bytes()).into(),
                version: 4,
                state,
                required_inbox: [6; 32],
                role: 0,
                blinding: Sha256::digest([index.to_be_bytes().as_slice(), b"blind"].concat())
                    .into(),
            },
        });
    }
    FrozenEpoch(FrozenEpochState {
        community: [1; 32],
        issuer_key: cssr::certificate::RecordIssuer::new(&[19; 32]).public_key(),
        policy_epoch: 3,
        epoch: 2,
        period_seconds: 86400,
        frozen_at: 172800,
        configuration: vec![1],
        extension_configuration: vec![2],
        proof_scope: AccountProofScope {
            circuit_digest: [4; 32],
            verifying_key_digest: [5; 32],
        },
        frontiers,
    })
}

fn open_matches(
    publication: &RecordEpochPublication,
    private: &<Kem as hpke::Kem>::PrivateKey,
) -> Vec<Vec<u8>> {
    let blob = publication.common_object();
    assert_eq!(&blob[..OBJECT_PREFIX.len()], OBJECT_PREFIX);
    let offset = OBJECT_PREFIX.len();
    let count = u32::from_be_bytes(blob[offset..offset + 4].try_into().unwrap());
    let size = u32::from_be_bytes(blob[offset + 4..offset + 8].try_into().unwrap()) as usize;
    assert_eq!(count, publication.descriptor.leaf_count);
    assert_eq!(blob.len(), offset + 8 + count as usize * size);
    let aad = packet_aad(publication.descriptor()).unwrap();
    blob[offset + 8..]
        .chunks_exact(size)
        .filter_map(|packet| {
            let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&packet[..32]).unwrap();
            hpke::single_shot_open::<Aead, Kdf, Kem>(
                &hpke::OpModeR::Base,
                private,
                &enc,
                HPKE_INFO,
                &packet[32..],
                &aad,
            )
            .ok()
        })
        .collect()
}

fn assert_witness(
    publication: &RecordEpochPublication,
    plaintext: &[u8],
    expected_owner: [u8; 32],
) {
    let take = |offset| -> [u8; 32] { plaintext[offset..offset + 32].try_into().unwrap() };
    let leaf = czkp::record::Leaf {
        owner: take(0),
        version: u64::from_be_bytes(plaintext[32..40].try_into().unwrap()),
        state: take(40),
        required_inbox: take(72),
        blinding: take(104),
        role: plaintext[136],
    };
    assert_eq!(leaf.owner, expected_owner);
    let index = u32::from_be_bytes(plaintext[137..141].try_into().unwrap()) as usize;
    assert!(index < publication.descriptor.leaf_count as usize);
    czkp::record::verify_certificate(
        &publication.descriptor.issuer_key,
        &publication.descriptor.community,
        publication.descriptor.epoch,
        &leaf
            .commitment(
                &publication.descriptor.community,
                publication.descriptor.epoch,
            )
            .unwrap(),
        &plaintext[plaintext.len() - 64..],
    )
    .unwrap();
    let path = plaintext[141..plaintext.len() - 64]
        .as_chunks::<32>()
        .0
        .to_vec();
    let proof = rs_merkle::MerkleProof::<czkp::record::EpochTree>::new(path);
    assert!(
        proof.verify(
            publication.descriptor.root,
            &[index],
            &[leaf
                .commitment(
                    &publication.descriptor.community,
                    publication.descriptor.epoch
                )
                .unwrap()],
            (publication.descriptor.leaf_count as usize)
                .max(2)
                .next_power_of_two()
        )
    );
}

#[test]
fn whole_common_object_decrypts_only_own_unlabeled_witness() {
    for count in [1, 2, 3, 8] {
        let original = fixture(count);
        let publication = original
            .encrypt(&cssr::certificate::RecordIssuer::new(&[19; 32]))
            .unwrap();
        let digest: [u8; 32] = Sha256::digest(publication.common_object()).into();
        assert_eq!(digest, publication.descriptor.download_digest);
        for index in 0..count {
            let found = open_matches(&publication, &material(index).0);
            assert_eq!(found.len(), 1);
            assert_witness(
                &publication,
                &found[0],
                Sha256::digest(index.to_be_bytes()).into(),
            );
        }
        assert!(open_matches(&publication, &material(count).0).is_empty());
        let mut wrong_epoch = publication.clone();
        wrong_epoch.descriptor.epoch += 1;
        assert!(open_matches(&wrong_epoch, &material(0).0).is_empty());
        let mut wrong_root = publication.clone();
        wrong_root.descriptor.root[0] ^= 1;
        assert!(open_matches(&wrong_root, &material(0).0).is_empty());
        let mut wrong_scope = publication.clone();
        wrong_scope.descriptor.proof_scope.circuit_digest[0] ^= 1;
        assert!(open_matches(&wrong_scope, &material(0).0).is_empty());
        let repeated = original
            .encrypt(&cssr::certificate::RecordIssuer::new(&[19; 32]))
            .unwrap();
        assert_eq!(publication.descriptor.root, repeated.descriptor.root);
        assert_ne!(publication.common_object(), repeated.common_object());
        // The ledger publication method, rather than this private builder,
        // persists and returns the exact ORIGINAL bytes on a repeated epoch.
    }
}

#[test]
fn report_actual_five_thousand_member_download_and_trial_decryption() {
    let source = fixture(5000);
    let start = Instant::now();
    let publication = source
        .encrypt(&cssr::certificate::RecordIssuer::new(&[19; 32]))
        .unwrap();
    let build = start.elapsed();
    let start = Instant::now();
    let found = open_matches(&publication, &material(2718).0);
    let trial = start.elapsed();
    assert_eq!(found.len(), 1);
    assert_witness(
        &publication,
        &found[0],
        Sha256::digest(2718_u32.to_be_bytes()).into(),
    );
    eprintln!(
        "record epoch actual members=5000 bytes={} build_ms={} trial_all_ms={}",
        publication.common_object().len(),
        build.as_millis(),
        trial.as_millis()
    );
}

#[test]
fn common_object_issuer_and_download_bytes_are_authenticated_as_one_object() {
    let frozen = fixture(3);
    assert!(matches!(
        frozen.encrypt(&cssr::certificate::RecordIssuer::new(&[20; 32])),
        Err(Error::PolicyMismatch)
    ));
    let publication = frozen
        .encrypt(&cssr::certificate::RecordIssuer::new(&[19; 32]))
        .unwrap();
    publication
        .descriptor
        .check_object(&publication.object)
        .unwrap();
    for index in [
        0,
        OBJECT_PREFIX.len(),
        publication.object.len() / 2,
        publication.object.len() - 1,
    ] {
        let mut changed = publication.object.clone();
        changed[index] ^= 1;
        assert!(publication.descriptor.check_object(&changed).is_err());
    }
    assert!(
        publication
            .descriptor
            .check_object(&publication.object[..publication.object.len() - 1])
            .is_err()
    );
    let mut appended = publication.object.clone();
    appended.push(0);
    assert!(publication.descriptor.check_object(&appended).is_err());
}

#[test]
fn recovery_binds_real_signatures_to_only_the_original_acceptance() {
    use crate::storage::{AccountStorage, MemoryStore};
    // This tests private storage recovery and real issuer signatures. The
    // acceptance below is a transcript vector, never a substitute verified CAS.
    let frozen = fixture(1);
    let epoch = frozen.0.epoch;
    let leaf = frozen.0.frontiers[0].leaf.clone();
    let community = frozen.0.community;
    let leaf_commitment = leaf.commitment(&community, epoch).unwrap();
    let record_issuer = cssr::certificate::RecordIssuer::new(&[19; 32]);
    let issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    let period = |key: &cssr::certificate::CertificateIssuer, from: u64, until: Option<u64>| {
        czkp::issuer_keys::CertificateKeyPeriod {
            public_key: key.public_key().to_vec(),
            valid_from: from,
            valid_until: until,
        }
    };
    let ring = vec![period(&issuer, 1, None)];
    let policy = AccountPolicy {
        initial_credit: 3,
        maximum_available: 3,
        outgoing_reservation: 1,
        incoming_reservation: 1,
        policy_revision: 1,
        policy_valid_from: 1,
        policy_valid_until: 300000,
        newcomer_period: 100,
        rate_window: 10,
        newcomer_admissions: 8,
        maximum_admissions: 8,
        refill_period: 10,
        refill_units: 1,
        abandon_after: 100,
    };
    let accepted = AccountAcceptance {
        statement: AccountStatement {
            protocol_version: 2,
            community,
            owner: leaf.owner,
            policy_digest: policy.digest(&community).unwrap(),
            enrollment_root: [1; 32],
            now: 172800,
            valid_until: 172900,
            genesis: false,
            previous_version: 4,
            next_version: 5,
            previous_state: leaf.state,
            next_state: [2; 32],
            settlement_marker: [0; 32],
            policy,
        },
        request_id: [7; 32],
        request_digest: [8; 32],
        proof_scope: frozen.0.proof_scope.clone(),
        accepted_at: 172801,
        signature: String::new(),
    };
    let mut certificate = crate::extensions::EpochAncestryCertificate {
        community,
        owner: leaf.owner,
        epoch,
        root: [3; 32],
        frozen_leaf: leaf_commitment,
        state: accepted.statement.next_state,
        version: accepted.statement.next_version,
        proof_scope: accepted.proof_scope.clone(),
        issued_at: accepted.accepted_at,
        signature: vec![],
        record: czkp::record::SignedLeaf {
            leaf,
            signature: record_issuer
                .issue(&community, epoch, &leaf_commitment)
                .unwrap()
                .to_vec(),
        },
    };
    certificate.signature = issuer.sign(&certificate.body().bytes().unwrap()).to_vec();
    let mut store = MemoryStore::default();
    let mut tx = AccountStorage::transaction(&mut store).unwrap();
    retain(&mut tx, &accepted.statement.owner, Some(&certificate)).unwrap();
    tx.commit().unwrap();
    let mut tx = AccountStorage::transaction(&mut store).unwrap();
    assert!(
        recover(&mut tx, &accepted, None, &record_issuer.public_key())
            .unwrap()
            .is_none()
    );
    assert!(
        recover(&mut tx, &accepted, Some(&ring), &record_issuer.public_key()).unwrap()
            == Some(certificate.clone())
    );
    for variant in 0..6 {
        let mut changed = accepted.clone();
        match variant {
            0 => changed.statement.community[0] ^= 1,
            1 => changed.statement.next_state[0] ^= 1,
            2 => changed.statement.next_version += 1,
            3 => changed.proof_scope.circuit_digest[0] ^= 1,
            4 => changed.proof_scope.verifying_key_digest[0] ^= 1,
            _ => changed.accepted_at += 1,
        }
        assert!(matches!(
            recover(&mut tx, &changed, Some(&ring), &record_issuer.public_key()),
            Err(Error::Storage)
        ));
    }
    assert!(matches!(
        recover(
            &mut tx,
            &accepted,
            Some(
                &[period(
                    &cssr::certificate::CertificateIssuer::new(&[4; 32]).unwrap(),
                    1,
                    None
                )][..]
            ),
            &record_issuer.public_key()
        ),
        Err(Error::Storage)
    ));
    // The signing key verifies only inside its own period: retired before the
    // issuance the stored certificate fails, retired after it the certificate stands.
    let other = cssr::certificate::CertificateIssuer::new(&[4; 32]).unwrap();
    let rotated = |at: u64| vec![period(&issuer, 1, Some(at)), period(&other, at, None)];
    assert!(matches!(
        recover(
            &mut tx,
            &accepted,
            Some(&rotated(accepted.accepted_at)),
            &record_issuer.public_key()
        ),
        Err(Error::Storage)
    ));
    assert!(
        recover(
            &mut tx,
            &accepted,
            Some(&rotated(accepted.accepted_at + 1)),
            &record_issuer.public_key()
        )
        .unwrap()
            == Some(certificate.clone())
    );
    assert!(matches!(
        recover(
            &mut tx,
            &accepted,
            Some(&ring),
            &cssr::certificate::RecordIssuer::new(&[20; 32]).public_key()
        ),
        Err(Error::Storage)
    ));
    let mut altered = certificate.clone();
    altered.record.signature[0] ^= 1;
    retain(&mut tx, &accepted.statement.owner, Some(&altered)).unwrap();
    assert!(matches!(
        recover(&mut tx, &accepted, Some(&ring), &record_issuer.public_key()),
        Err(Error::Storage)
    ));
    tx.rollback().unwrap();
    let mut tx = AccountStorage::transaction(&mut store).unwrap();
    assert!(
        recover(&mut tx, &accepted, Some(&ring), &record_issuer.public_key()).unwrap()
            == Some(certificate)
    );
    retain(&mut tx, &accepted.statement.owner, None).unwrap();
    assert!(
        recover(&mut tx, &accepted, Some(&ring), &record_issuer.public_key())
            .unwrap()
            .is_none()
    );
}

// Join-time record leaf (certify_join) tests. A genesis accepted while a
// published epoch is current has no frozen lineage, so the record issuer
// signs a leaf of the exact accepted genesis frontier for this epoch instead
// of a frozen descendant. These tests drive certify_join through a real
// transaction; no proof fixtures are needed.
use crate::{
    accounting::AccountPolicy,
    accounting_ledger::AccountLedgerPolicy,
    admission::AdmissionTrust,
    artifacts::ArtifactBinding,
    extensions::{ExtensionPolicy, ExtensionStatement, Extensions},
    storage::{AccountStorage, MemoryStore},
    verification::{Budget, ExtensionLimits},
};

struct JoinStubVerifier {
    scope: AccountProofScope,
}
impl crate::extensions::sealed::Sealed for JoinStubVerifier {}
impl crate::extensions::ExtensionVerifier for JoinStubVerifier {
    fn scope(&self) -> AccountProofScope {
        self.scope.clone()
    }
    fn cancellation(&self) -> crate::verification::NativeExtensionCancellation {
        unimplemented!("join-leaf tests never schedule native verification work")
    }
    fn require_record_epoch(&self) -> Result<(), Error> {
        Ok(())
    }
    fn verify(&self, _statement: &ExtensionStatement, _proof: &[u8]) -> Result<(), Error> {
        Err(Error::UnsupportedCapability)
    }
    fn verify_anonymous(
        &self,
        _statement: &ExtensionStatement,
        _proof: &[u8],
    ) -> Result<(), Error> {
        Err(Error::UnsupportedCapability)
    }
}

struct JoinWorld {
    store: MemoryStore,
    community: [u8; 32],
    owner: [u8; 32],
    state: [u8; 32],
    scope: AccountProofScope,
    policy: AccountLedgerPolicy,
    descriptor: czkp::record::Epoch,
    configuration: Vec<u8>,
    extensions: Extensions,
    issuer: cssr::certificate::CertificateIssuer,
    record_issuer: cssr::certificate::RecordIssuer,
}

fn join_world() -> JoinWorld {
    let scope = AccountProofScope {
        circuit_digest: [4; 32],
        verifying_key_digest: [5; 32],
    };
    let policy = AccountLedgerPolicy {
        account: AccountPolicy {
            initial_credit: 3,
            maximum_available: 4,
            outgoing_reservation: 1,
            incoming_reservation: 1,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 2000,
            newcomer_period: 100,
            rate_window: 1000,
            newcomer_admissions: 2,
            maximum_admissions: 4,
            refill_period: 100,
            refill_units: 1,
            abandon_after: 1000,
        },
        max_authorization_seconds: 100,
        max_proof_bytes: 1024 * 1024,
        checkpoint_period_seconds: 1000,
    };
    let signer = csgn::Signer::new(
        "community-example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        1,
        2000,
    )
    .unwrap();
    let trust = AdmissionTrust {
        community_id: "community-example".into(),
        policy_digest: "opaque-policy-digest".into(),
        policy_keys: signer.key_ring().clone(),
    };
    let configuration = super::tuning::config_bytes(&trust, &policy, &scope, [9; 32], 0).unwrap();
    let record_issuer = cssr::certificate::RecordIssuer::new(&[19; 32]);
    // Epoch 2 on a 100-second period: starts_at 200, expires_at 300.
    let descriptor = czkp::record::Epoch {
        purpose: czkp::record::Purpose::RecordEpochV3,
        community: [1; 32],
        policy_epoch: 1,
        epoch: 2,
        starts_at: 200,
        expires_at: 300,
        root: [3; 32],
        issuer_key: record_issuer.public_key(),
        proof_scope: scope.clone(),
        leaf_count: 4,
        download_digest: [6; 32],
        download_bytes: 1024,
    };
    let extension_configuration = b"join-test-extension-config".to_vec();
    let extensions = Extensions {
        artifact_binding: ArtifactBinding {
            manifest_sha256: [7; 32],
        },
        activation_anchor: Vec::new(),
        policy: ExtensionPolicy {
            revision: 1,
            public_record_quorum: 5,
            change_token_cost: 1,
            deposit_delay_seconds: 10,
            minimum_deposit_batch: 2,
            standing_policy_digest: [9; 32],
        },
        verifier: Box::new(JoinStubVerifier {
            scope: scope.clone(),
        }),
        config: extension_configuration.clone(),
        budget: Budget::new(
            "community-example",
            ExtensionLimits {
                global_burst: 1000,
                subject_burst: 500,
                replenish: std::time::Duration::from_secs(1),
                maximum_keys: std::num::NonZeroUsize::new(32).unwrap(),
            },
        )
        .unwrap(),
    };
    let mut store = MemoryStore::default();
    let mut tx = AccountStorage::transaction(&mut store).unwrap();
    tx.put(
        ANCHOR,
        &PublishedAnchor {
            descriptor: descriptor.clone(),
            period_seconds: 100,
            frozen_at: 200,
            configuration: configuration.clone(),
            extension_configuration,
        },
    )
    .unwrap();
    tx.commit().unwrap();
    JoinWorld {
        store,
        community: [1; 32],
        owner: [7; 32],
        state: [2; 32],
        scope,
        policy,
        descriptor,
        configuration,
        extensions,
        issuer: cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap(),
        record_issuer,
    }
}

impl JoinWorld {
    fn acceptance(&self, accepted_at: u64) -> AccountAcceptance {
        AccountAcceptance {
            statement: AccountStatement {
                protocol_version: 2,
                community: self.community,
                owner: self.owner,
                policy_digest: [8; 32],
                enrollment_root: [1; 32],
                now: 200,
                valid_until: 400,
                genesis: true,
                previous_version: 0,
                next_version: 0,
                previous_state: [0; 32],
                next_state: self.state,
                settlement_marker: [0; 32],
                policy: self.policy.account.clone(),
            },
            request_id: [7; 32],
            request_digest: [8; 32],
            proof_scope: self.scope.clone(),
            accepted_at,
            signature: String::new(),
        }
    }

    fn certify(
        &mut self,
        accepted: &AccountAcceptance,
    ) -> Result<Option<crate::extensions::EpochAncestryCertificate>, Error> {
        let mut tx = AccountStorage::transaction(&mut self.store).unwrap();
        certify_join(
            &mut tx,
            accepted,
            &self.configuration,
            &self.extensions,
            &self.issuer,
            &self.record_issuer,
        )
    }
}

#[test]
fn join_leaf_issues_exactly_one_signed_leaf_for_a_genesis_inside_the_window() {
    let mut world = join_world();
    let accepted = world.acceptance(250);
    let Some(certificate) = world.certify(&accepted).unwrap() else {
        panic!("genesis inside frozen_at <= accepted_at < expires_at gets a join leaf");
    };
    assert_eq!(certificate.community, world.community);
    assert_eq!(certificate.owner, world.owner);
    assert_eq!(certificate.epoch, world.descriptor.epoch);
    assert_eq!(certificate.root, world.descriptor.root);
    assert_eq!(certificate.state, accepted.statement.next_state);
    assert_eq!(certificate.version, accepted.statement.next_version);
    assert_eq!(certificate.proof_scope, accepted.proof_scope);
    assert_eq!(certificate.issued_at, accepted.accepted_at);
    // The single SignedLeaf commits to the exact accepted genesis state.
    assert_eq!(certificate.record.leaf.owner, world.owner);
    assert_eq!(certificate.record.leaf.version, 0);
    assert_eq!(certificate.record.leaf.state, world.state);
    assert_eq!(
        certificate.record.leaf.required_inbox,
        crate::extensions::Inbox::default().root
    );
    let commitment = certificate
        .record
        .leaf
        .commitment(&world.community, world.descriptor.epoch)
        .unwrap();
    assert_eq!(certificate.frozen_leaf, commitment);
    // The join certificate carries no tree path: only the record issuer's
    // signature over the blinded leaf authenticates it for this epoch.
    czkp::record::verify_certificate(
        &world.descriptor.issuer_key,
        &world.community,
        world.descriptor.epoch,
        &certificate.frozen_leaf,
        &certificate.record.signature,
    )
    .unwrap();
    certificate.verify(&world.issuer.public_key()).unwrap();
}

#[test]
fn join_leaf_refuses_a_member_with_a_prior_frontier() {
    let mut world = join_world();
    let accepted = world.acceptance(250);
    let mut tx = AccountStorage::transaction(&mut world.store).unwrap();
    tx.put(
        &key(1, &[&world.owner]),
        &Frontier {
            root_key: [9; 32],
            root_revision: 0,
            version: 0,
            state: world.state,
            latest_request: [7; 32],
            record_ancestry: None,
        },
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(world.certify(&accepted).unwrap().is_none());
}

#[test]
fn join_leaf_refuses_a_state_mismatch() {
    let mut world = join_world();
    let accepted = world.acceptance(250);
    // A proof scope outside the published epoch carries no join leaf.
    let mut wrong_scope = accepted.clone();
    wrong_scope.proof_scope.circuit_digest = [9; 32];
    assert!(world.certify(&wrong_scope).unwrap().is_none());
    // A statement for another community carries no join leaf either.
    let mut wrong_community = accepted.clone();
    wrong_community.statement.community = [9; 32];
    assert!(world.certify(&wrong_community).unwrap().is_none());
}

#[test]
fn join_leaf_refuses_acceptances_outside_the_frozen_window() {
    let mut world = join_world();
    // frozen_at is 200 and the epoch expires at 300.
    assert!(world.certify(&world.acceptance(199)).unwrap().is_none());
    assert!(world.certify(&world.acceptance(300)).unwrap().is_none());
}

#[test]
fn join_leaf_recover_reserves_the_identical_leaf() {
    let mut world = join_world();
    let accepted = world.acceptance(250);
    let Some(certificate) = world.certify(&accepted).unwrap() else {
        panic!("genesis inside the window gets a join leaf");
    };
    let mut tx = AccountStorage::transaction(&mut world.store).unwrap();
    retain(&mut tx, &world.owner, Some(&certificate)).unwrap();
    tx.commit().unwrap();
    let ring = vec![czkp::issuer_keys::CertificateKeyPeriod {
        public_key: world.issuer.public_key().to_vec(),
        valid_from: 1,
        valid_until: None,
    }];
    let mut tx = AccountStorage::transaction(&mut world.store).unwrap();
    let Some(reissued) = recover(
        &mut tx,
        &accepted,
        Some(&ring),
        &world.record_issuer.public_key(),
    )
    .unwrap() else {
        panic!("retained join leaf is re-served");
    };
    assert_eq!(
        serde_json::to_vec(&reissued).unwrap(),
        serde_json::to_vec(&certificate).unwrap()
    );
}

#[test]
fn join_leaf_certificate_verifies_under_the_epoch_issuer_key_and_rejects_tampering() {
    let mut world = join_world();
    assert_eq!(
        world.descriptor.issuer_key,
        world.record_issuer.public_key()
    );
    let accepted = world.acceptance(250);
    let Some(certificate) = world.certify(&accepted).unwrap() else {
        panic!("genesis inside the window gets a join leaf");
    };
    certificate.verify(&world.issuer.public_key()).unwrap();
    czkp::record::verify_certificate(
        &world.descriptor.issuer_key,
        &world.community,
        world.descriptor.epoch,
        &certificate.frozen_leaf,
        &certificate.record.signature,
    )
    .unwrap();
    // Another issuer's key verifies neither the ancestry body nor the leaf.
    let other = cssr::certificate::CertificateIssuer::new(&[4; 32]).unwrap();
    assert!(certificate.verify(&other.public_key()).is_err());
    // A tampered leaf no longer matches the record issuer's certificate.
    let mut tampered_leaf = certificate.clone();
    tampered_leaf.record.leaf.state = [3; 32];
    let tampered_commitment = tampered_leaf
        .record
        .leaf
        .commitment(&world.community, world.descriptor.epoch)
        .unwrap();
    assert_ne!(tampered_commitment, certificate.frozen_leaf);
    assert!(
        czkp::record::verify_certificate(
            &world.descriptor.issuer_key,
            &world.community,
            world.descriptor.epoch,
            &tampered_commitment,
            &tampered_leaf.record.signature,
        )
        .is_err()
    );
    // A tampered record signature fails outright.
    let mut tampered_signature = certificate.clone();
    tampered_signature.record.signature[0] ^= 1;
    assert!(
        czkp::record::verify_certificate(
            &world.descriptor.issuer_key,
            &world.community,
            world.descriptor.epoch,
            &certificate.frozen_leaf,
            &tampered_signature.record.signature,
        )
        .is_err()
    );
}

// K1 S4 (decided 2026-10-29): a recipient replacement takes effect only at the NEXT
// record-epoch boundary, never mid-epoch, and the previous recipient keeps serving the
// epoch in flight, so its witness still opens under the old key.
#[test]
fn recipient_replacement_takes_effect_only_at_the_next_epoch_boundary() {
    let period = 100;
    let base = [41; 32];
    // Registered at 250: inside epoch 2 (200..300).
    let replacements = vec![(250, [42; 32])];
    let at = |epoch: u64| super::effective_recipient(base, &replacements, epoch * period);
    // The epoch in flight (2) and every earlier one keep the old recipient.
    assert_eq!(at(1), base);
    assert_eq!(at(2), base);
    // From the next boundary on, the replacement.
    assert_eq!(at(3), [42; 32]);
    assert_eq!(at(9), [42; 32]);
    // Registered exactly at a boundary (300 = start of epoch 3) is inside epoch 3: next is 4.
    let boundary = vec![(300, [43; 32])];
    assert_eq!(super::effective_recipient(base, &boundary, 300), base);
    assert_eq!(super::effective_recipient(base, &boundary, 400), [43; 32]);
    // Two replacements: each epoch resolves to the last one registered before its start.
    let two = vec![(250, [42; 32]), (450, [44; 32])];
    assert_eq!(super::effective_recipient(base, &two, 400), [42; 32]);
    assert_eq!(super::effective_recipient(base, &two, 500), [44; 32]);
}

// K1 S4 compaction (manager decision on review M2, 2026-11-14). The registry keeps only
// what decision 2026-10-29 (a)-(c) needs: the current recipient, at most one pending move
// per record epoch with its acceptance time until an install folds it, and the previous
// recipient only while the epoch in flight still resolves to it. These tests run the real
// freeze (`prepare_in`), encryption and install (`install_in`) over a MemoryStore.
mod recipient_compaction {
    use super::*;
    use crate::storage::{AccountStorage, MemoryStore};

    const PERIOD: u64 = 100;
    const OWNER: [u8; 32] = [77; 32];

    fn world() -> MemoryStore {
        let mut store = MemoryStore::default();
        let mut tx = AccountStorage::transaction(&mut store).unwrap();
        tx.put(
            &crate::storage::key(1, &[&OWNER]),
            &Frontier {
                root_key: [1; 32],
                root_revision: 1,
                version: 1,
                state: [2; 32],
                latest_request: [3; 32],
                record_ancestry: None,
            },
        )
        .unwrap();
        tx.commit().unwrap();
        store
    }

    fn recipient(index: u32) -> [u8; 32] {
        material(index).1
    }

    fn move_to(
        store: &mut MemoryStore,
        index: u32,
        lineage_epoch: u64,
        now: u64,
    ) -> Result<(), Error> {
        let mut tx = AccountStorage::transaction(store).unwrap();
        move_recipient_in(&mut tx, &OWNER, recipient(index), lineage_epoch, now)?;
        tx.commit()
    }

    /// Freeze, encrypt and install record epoch `epoch` at its 60th second.
    fn install(store: &mut MemoryStore, epoch: u64) -> (FrozenEpoch, RecordEpochPublication) {
        let issuer = cssr::certificate::RecordIssuer::new(&[19; 32]);
        let scope = AccountProofScope {
            circuit_digest: [4; 32],
            verifying_key_digest: [5; 32],
        };
        let now = epoch * PERIOD + 60;
        let mut tx = AccountStorage::transaction(store).unwrap();
        let frozen = prepare::prepare_in(
            &mut tx,
            &prepare::Inputs {
                community: [1; 32],
                issuer_key: issuer.public_key(),
                policy_epoch: 1,
                epoch,
                period_seconds: PERIOD,
                now,
                configuration: &[1],
                extension_configuration: &[2],
                proof_scope: &scope,
            },
            &|| now,
        )
        .unwrap();
        let published = frozen.encrypt(&issuer).unwrap();
        install::install_in(&mut tx, &frozen, &published, now).unwrap();
        tx.commit().unwrap();
        (frozen, published)
    }

    /// The stored recipient and the pending moves (with their acceptance times).
    type Registry = ([u8; 32], Option<Vec<(u64, [u8; 32])>>);

    fn stored(store: &mut MemoryStore) -> Registry {
        let mut tx = AccountStorage::transaction(store).unwrap();
        (
            tx.get(&recipient_key(&OWNER)).unwrap().unwrap(),
            tx.get(&recipient_replacements_key(&OWNER)).unwrap(),
        )
    }

    // 40 rotations, one per record epoch, each between that epoch's start and its
    // install: every move succeeds; the epoch in flight still goes to the previous
    // recipient, whose witness opens and verifies, the new one opens nothing; after
    // each install the registry holds the current recipient alone, no past key, no time.
    #[test]
    fn forty_rotations_succeed_and_every_install_leaves_only_the_current_recipient() {
        let mut store = world();
        move_to(&mut store, 0, 1, 50).unwrap();
        install(&mut store, 1);
        for index in 1..=40u32 {
            let epoch = u64::from(index) + 1;
            move_to(&mut store, index, epoch, epoch * PERIOD + 10).unwrap();
            let (frozen, published) = install(&mut store, epoch);
            // (c): the epoch in flight keeps the previous recipient.
            assert_eq!(frozen.0.frontiers[0].recipient_key, recipient(index - 1));
            let witnesses = open_matches(&published, &material(index - 1).0);
            assert_eq!(witnesses.len(), 1);
            assert_witness(&published, &witnesses[0], OWNER);
            assert!(open_matches(&published, &material(index).0).is_empty());
            // After the install: only the current recipient, no history, no timestamp.
            assert_eq!(stored(&mut store), (recipient(index), None));
        }
        // The next epoch is witnessed to the last recipient.
        let (_, published) = install(&mut store, 42);
        assert_eq!(open_matches(&published, &material(40).0).len(), 1);
    }

    // Twenty moves inside one record epoch: all succeed, exactly one pending move with
    // its acceptance time is kept (a later move in the same epoch supersedes it, since
    // no boundary lies between them), and the epoch in flight resolves to the previous
    // recipient while the next epoch resolves to the last move.
    #[test]
    fn many_moves_inside_one_epoch_keep_one_pending_move() {
        let mut store = world();
        move_to(&mut store, 0, 1, 50).unwrap();
        install(&mut store, 1);
        for index in 1..=20u32 {
            move_to(
                &mut store,
                index,
                u64::from(index) + 1,
                270 + u64::from(index),
            )
            .unwrap();
        }
        assert_eq!(
            stored(&mut store),
            (recipient(0), Some(vec![(290, recipient(20))]))
        );
        let mut tx = AccountStorage::transaction(&mut store).unwrap();
        assert_eq!(
            recipient_for_epoch(&mut tx, &OWNER, 200).unwrap(),
            Some(recipient(0))
        );
        assert_eq!(
            recipient_for_epoch(&mut tx, &OWNER, 300).unwrap(),
            Some(recipient(20))
        );
        drop(tx);
        // A move accepted after epoch 2 was installed, still inside epoch 2, serves epoch 3.
        install(&mut store, 2);
        assert_eq!(stored(&mut store), (recipient(20), None));
        move_to(&mut store, 21, 22, 295).unwrap();
        let (frozen, _) = install(&mut store, 3);
        assert_eq!(frozen.0.frontiers[0].recipient_key, recipient(21));
        assert_eq!(stored(&mut store), (recipient(21), None));
    }

    // Before any record epoch was installed the ledger knows no period, so pending moves
    // cannot be folded: they are bounded per install interval (16), never per lifetime;
    // the first install folds them and moves succeed again.
    #[test]
    fn pending_moves_before_the_first_install_are_bounded_until_it_folds_them() {
        let mut store = world();
        move_to(&mut store, 0, 1, 10).unwrap();
        for index in 1..=16u32 {
            move_to(
                &mut store,
                index,
                u64::from(index) + 1,
                10 + u64::from(index),
            )
            .unwrap();
        }
        assert_eq!(move_to(&mut store, 17, 18, 40), Err(Error::Capacity));
        let (frozen, _) = install(&mut store, 1);
        assert_eq!(frozen.0.frontiers[0].recipient_key, recipient(16));
        assert_eq!(stored(&mut store), (recipient(16), None));
        for index in 17..=40u32 {
            move_to(
                &mut store,
                index,
                u64::from(index) + 1,
                150 + u64::from(index),
            )
            .unwrap();
        }
    }

    // The fold at install relies on pending moves sorted by acceptance time; a move
    // whose server time steps back behind the newest pending move is refused, and the
    // registry is unchanged.
    #[test]
    fn a_move_behind_the_newest_pending_move_is_refused() {
        let mut store = world();
        move_to(&mut store, 0, 1, 50).unwrap();
        install(&mut store, 1);
        move_to(&mut store, 1, 2, 250).unwrap();
        let before = stored(&mut store);
        assert_eq!(move_to(&mut store, 2, 3, 190), Err(Error::ClockRollback));
        assert_eq!(stored(&mut store), before);
        // The same time, or later, moves as usual.
        move_to(&mut store, 2, 3, 250).unwrap();
        let (frozen, _) = install(&mut store, 2);
        assert_eq!(frozen.0.frontiers[0].recipient_key, recipient(0));
        assert_eq!(stored(&mut store), (recipient(2), None));
    }

    // Replay protection is unchanged: the same or an older lineage epoch never moves it.
    #[test]
    fn a_move_needs_a_strictly_newer_lineage_epoch() {
        let mut store = world();
        move_to(&mut store, 0, 1, 50).unwrap();
        install(&mut store, 1);
        move_to(&mut store, 1, 2, 150).unwrap();
        assert_eq!(move_to(&mut store, 2, 2, 151), Err(Error::Replay));
        assert_eq!(move_to(&mut store, 0, 1, 152), Err(Error::Replay));
        move_to(&mut store, 1, 2, 153).unwrap();
    }
}
