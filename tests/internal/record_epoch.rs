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
    };
    assert_eq!(leaf.owner, expected_owner);
    let index = u32::from_be_bytes(plaintext[136..140].try_into().unwrap()) as usize;
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
    let path = plaintext[140..plaintext.len() - 64]
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
        recover(
            &mut tx,
            &accepted,
            Some(&issuer),
            &record_issuer.public_key()
        )
        .unwrap()
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
            recover(
                &mut tx,
                &changed,
                Some(&issuer),
                &record_issuer.public_key()
            ),
            Err(Error::Storage)
        ));
    }
    assert!(matches!(
        recover(
            &mut tx,
            &accepted,
            Some(&cssr::certificate::CertificateIssuer::new(&[4; 32]).unwrap()),
            &record_issuer.public_key()
        ),
        Err(Error::Storage)
    ));
    assert!(matches!(
        recover(
            &mut tx,
            &accepted,
            Some(&issuer),
            &cssr::certificate::RecordIssuer::new(&[20; 32]).public_key()
        ),
        Err(Error::Storage)
    ));
    let mut altered = certificate.clone();
    altered.record.signature[0] ^= 1;
    retain(&mut tx, &accepted.statement.owner, Some(&altered)).unwrap();
    assert!(matches!(
        recover(
            &mut tx,
            &accepted,
            Some(&issuer),
            &record_issuer.public_key()
        ),
        Err(Error::Storage)
    ));
    tx.rollback().unwrap();
    let mut tx = AccountStorage::transaction(&mut store).unwrap();
    assert!(
        recover(
            &mut tx,
            &accepted,
            Some(&issuer),
            &record_issuer.public_key()
        )
        .unwrap()
            == Some(certificate)
    );
    retain(&mut tx, &accepted.statement.owner, None).unwrap();
    assert!(
        recover(
            &mut tx,
            &accepted,
            Some(&issuer),
            &record_issuer.public_key()
        )
        .unwrap()
        .is_none()
    );
}
