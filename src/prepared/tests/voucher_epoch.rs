//! Voucher presentation ABI and the native issuer certificate check, not proof acceptance.
use super::*;
use crate::extensions::{VoucherPresentation, VoucherPurpose};
use ed25519_dalek::{Signer, SigningKey};

/// An issue claim with `units` distinct reserved slots (the rest zero).
fn issue(uses: u32, signoff_standing: u64, units: u8) -> VoucherPurpose {
    VoucherPurpose::Issue {
        uses,
        signoff_standing,
        nullifiers: (1..=units)
            .map(|index| {
                let mut nullifier = [0; 32];
                nullifier[31] = index;
                nullifier
            })
            .collect(),
    }
}

fn presentation(purpose: VoucherPurpose) -> VoucherPresentation {
    let issuer = SigningKey::from_bytes(&[31; 32]);
    let leaf = [7; 32];
    VoucherPresentation {
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
        blinded_leaf: leaf,
        certificate: issuer
            .sign(&czkp::record::certificate_bytes(&[1; 32], 2, &leaf).unwrap())
            .to_bytes()
            .to_vec(),
        purpose,
        now: 250,
        binding: [9; 32],
    }
}

fn statement(presentation: VoucherPresentation) -> ExtensionStatement {
    ExtensionStatement::VoucherEpoch {
        policy: policy(),
        presentation,
    }
}

#[test]
fn voucher_public_abi_has_the_circuit_width_and_order() {
    let issue = presentation(issue(3, 4, 3));
    let prepared = prepare(&statement(issue.clone()), &anonymous()).unwrap();
    assert_eq!(prepared.len(), 1);
    let fields = &prepared[0].inputs;
    assert_eq!(fields.len(), crate::artifacts::VOUCHER_EPOCH_WIDTH);
    for (start, expected) in [
        (37, issue.epoch.issuer_key.as_slice()),
        (69, issue.certificate.as_slice()),
        (133, issue.epoch.proof_scope.circuit_digest.as_slice()),
        (165, issue.epoch.proof_scope.verifying_key_digest.as_slice()),
        (197, issue.epoch.community.as_slice()),
        (232, issue.epoch.root.as_slice()),
        (265, issue.blinded_leaf.as_slice()),
        (332, issue.binding.as_slice()),
    ] {
        assert_eq!(
            values(&fields[start..start + expected.len()]),
            expected.iter().map(|v| u64::from(*v)).collect::<Vec<_>>()
        );
    }
    assert_eq!(values(&fields[229..232]), [2, 200, 300]);
    assert_eq!(scalar_value(&fields[264]), 9);
    assert_eq!(values(&fields[297..300]), [0, 3, 250]);
    assert_eq!(values(&fields[300..332]), [0; 32]);
    // Sign-off threshold, then one field per nullifier slot (spent slots first).
    assert_eq!(scalar_value(&fields[364]), 4);
    assert_eq!(values(&fields[365..367]), [1, 2]);
    assert_eq!(values(&fields[367..368]), [3]);
    assert_eq!(values(&fields[368..381]), [0; 13]);

    let post = presentation(VoucherPurpose::Post { tag: [5; 32] });
    let prepared = prepare(&statement(post), &anonymous()).unwrap();
    let fields = &prepared[0].inputs;
    assert_eq!(values(&fields[297..300]), [1, 0, 250]);
    assert_eq!(values(&fields[300..332]), [5; 32]);
    assert_eq!(scalar_value(&fields[364]), 0);
    assert_eq!(values(&fields[365..381]), [0; 16]);
}

#[test]
fn voucher_presentation_refuses_bad_shape_scope_and_certificate() {
    let good = presentation(issue(1, 0, 1));
    let mut cases = Vec::new();
    for mutate in [
        |p: &mut VoucherPresentation| p.purpose = issue(0, 0, 1),
        |p: &mut VoucherPresentation| p.purpose = issue(1, 0, 0),
        |p: &mut VoucherPresentation| p.purpose = issue(1, 0, 2),
        |p: &mut VoucherPresentation| p.purpose = issue(2, czkp::MAX_INTEGER + 1, 2),
        |p: &mut VoucherPresentation| {
            // A zero nullifier.
            p.purpose = issue(1, 0, 1);
            let VoucherPurpose::Issue { nullifiers, .. } = &mut p.purpose else {
                unreachable!()
            };
            nullifiers[0] = [0; 32];
        },
        |p: &mut VoucherPresentation| {
            p.purpose = issue(2, 0, 2);
            let VoucherPurpose::Issue { nullifiers, .. } = &mut p.purpose else {
                unreachable!()
            };
            nullifiers[1] = nullifiers[0];
        },
        |p: &mut VoucherPresentation| p.purpose = VoucherPurpose::Post { tag: [0; 32] },
        |p: &mut VoucherPresentation| p.binding = [0; 32],
        |p: &mut VoucherPresentation| p.certificate.truncate(63),
        |p: &mut VoucherPresentation| p.certificate[0] ^= 1,
        |p: &mut VoucherPresentation| p.blinded_leaf[0] ^= 1,
        |p: &mut VoucherPresentation| p.epoch.proof_scope.circuit_digest[0] ^= 1,
        |p: &mut VoucherPresentation| p.epoch.root = [0; 32],
        |p: &mut VoucherPresentation| p.epoch.leaf_count = 0,
        |p: &mut VoucherPresentation| p.epoch.expires_at = p.epoch.starts_at,
    ] {
        let mut changed = good.clone();
        mutate(&mut changed);
        cases.push(changed);
    }
    for changed in cases {
        assert!(prepare(&statement(changed), &anonymous()).is_err());
    }
}
