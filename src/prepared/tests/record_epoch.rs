//! Original R2 ABI and real issuer signature checks, not proof acceptance.
use super::*;
use ed25519_dalek::{Signer, SigningKey};

fn record() -> czkp::record::Record {
    let issuer = SigningKey::from_bytes(&[31; 32]);
    let leaf = [7; 32];
    czkp::record::Record {
        epoch: czkp::record::Epoch {
            purpose: czkp::record::Purpose::RecordEpochV3,
            community: [1; 32],
            policy_epoch: 4,
            epoch: 2,
            starts_at: 200,
            expires_at: 300,
            root: [3; 32],
            issuer_key: issuer.verifying_key().to_bytes(),
            proof_scope: scope(),
            leaf_count: 9,
            download_digest: [8; 32],
            download_bytes: 100,
        },
        owner: [2; 32],
        presentation_key: SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes(),
        blinded_leaf: leaf,
        certificate: issuer
            .sign(&czkp::record::certificate_bytes(&[1; 32], 2, &leaf).unwrap())
            .to_bytes()
            .to_vec(),
        shares: Some([2500, 6000, 1500]),
    }
}

fn statement(record: czkp::record::Record) -> ExtensionStatement {
    ExtensionStatement::RecordEpoch {
        policy: policy(),
        record,
    }
}

#[test]
fn original_r2_public_abi_preserves_each_field_and_the_two_key_limbs() {
    let record = record();
    let prepared = prepare(&statement(record.clone()), &anonymous()).unwrap();
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].proof, [1, 2]); // Opaque framing fixture, never a valid proof.
    let fields = &prepared[0].inputs;
    assert_eq!(fields.len(), 303);
    assert_eq!(values(&fields[..5]), [2, 5, 3, 10, 2]);
    // Offsets are the original record_epoch Noir public parameter order.
    for (start, expected) in [
        (5, record.epoch.issuer_key.as_slice()),
        (37, record.certificate.as_slice()),
        (101, record.epoch.proof_scope.circuit_digest.as_slice()),
        (
            133,
            record.epoch.proof_scope.verifying_key_digest.as_slice(),
        ),
        (165, record.epoch.community.as_slice()),
        (197, record.owner.as_slice()),
        (232, record.epoch.root.as_slice()),
        (265, record.blinded_leaf.as_slice()),
    ] {
        assert_eq!(
            values(&fields[start..start + expected.len()]),
            expected.iter().map(|v| u64::from(*v)).collect::<Vec<_>>()
        );
    }
    assert_eq!(values(&fields[229..232]), [2, 200, 300]);
    assert_eq!(scalar_value(&fields[264]), 9);
    let key = fields[297..299]
        .iter()
        .flat_map(|f| {
            assert_eq!(&f[..16], &[0; 16]);
            f[16..].iter().copied()
        })
        .collect::<Vec<_>>();
    assert_eq!(key, record.presentation_key);
    assert_eq!(values(&fields[299..]), [1, 2500, 6000, 1500]);
    for field in fields {
        czkp::field(field, false).unwrap();
    }

    let mut below_quorum = record;
    below_quorum.shares = None;
    let prepared = prepare(&statement(below_quorum), &anonymous()).unwrap();
    assert_eq!(values(&prepared[0].inputs[299..]), [0, 0, 0, 0]);
}

#[test]
fn certificate_and_both_group_scope_digests_are_required_before_native_proof_work() {
    for variant in 0..8 {
        let mut record = record();
        match variant {
            0 => record.epoch.proof_scope.circuit_digest[0] ^= 1,
            1 => record.epoch.proof_scope.verifying_key_digest[0] ^= 1,
            2 => record.certificate[0] ^= 1,
            3 => {
                record.epoch.issuer_key =
                    SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes()
            }
            4 => record.epoch.community[0] ^= 1,
            5 => {
                record.epoch.epoch = 3;
                record.epoch.starts_at = 300;
                record.epoch.expires_at = 400;
            }
            6 => record.blinded_leaf[31] ^= 1,
            _ => record.certificate.pop().map(|_| ()).unwrap(),
        }
        assert!(
            prepare(&statement(record), &anonymous()).is_err(),
            "variant {variant}"
        );
    }
    // A valid certificate is still not a proof and cannot replace its frame.
    for proof in [
        b"{}".as_slice(),
        b"{\"version\":1,\"proofs\":[]}".as_slice(),
        b"{\"version\":1,\"proofs\":[{\"proof\":\"01\"},{\"proof\":\"02\"}]}".as_slice(),
    ] {
        assert!(prepare(&statement(record()), proof).is_err());
    }
}
