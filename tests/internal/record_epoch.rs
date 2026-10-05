//! Actual maintained HPKE/tree interoperability and measured common-download cost.
//! Synthetic frontier values exercise the format; they are not admitted accounts.
use super::*;
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
    let path = plaintext[140..]
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
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
        let publication = original.encrypt().unwrap();
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
        let repeated = original.encrypt().unwrap();
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
    let publication = source.encrypt().unwrap();
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
