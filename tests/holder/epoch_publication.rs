//! Project the genuine durable epoch; faults never replace a proof or signer.
use cblc::{accounting::AccountProofVerifier, accounting_ledger::AccountLedger};
use serde_json::{Value, json};

pub fn legacy<V: AccountProofVerifier>(ledger: &mut AccountLedger<V>) {
    let issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    let material = ledger.public_verifier_material(1, 1, &issuer).unwrap();
    assert!(material.record_epoch.is_none());
    let bytes = serde_json::to_vec(&material).unwrap();
    assert!(
        serde_json::from_slice::<Value>(&bytes)
            .unwrap()
            .get("recordEpoch")
            .is_none()
    );
    let decoded: cblc::publication::PublicVerifierMaterial =
        serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, material);
}

pub fn published<V: AccountProofVerifier>(
    ledger: &mut AccountLedger<V>,
    store: &mut cssr::LibsqlStore,
    publication: &cblc::accounting_ledger::record_epoch::RecordEpochPublication,
) {
    let issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    let material = ledger.public_verifier_material(1, 1, &issuer).unwrap();
    let descriptor = material.record_epoch.as_ref().unwrap();
    assert_eq!(descriptor, publication.descriptor());
    descriptor
        .check_object(publication.common_object())
        .unwrap();
    let wire = serde_json::to_vec(&material).unwrap();
    assert_eq!(
        serde_json::from_slice::<cblc::publication::PublicVerifierMaterial>(&wire).unwrap(),
        material
    );
    // Record expiry is a separate capability check, not an expiry of unrelated
    // public policy. No feed deadline or signing behavior changes in this slice.
    material
        .validate_at(&material.community, descriptor.expires_at)
        .unwrap();
    assert!(descriptor.check_time(descriptor.expires_at).is_err());
    assert!(ledger.public_verifier_material(2, 2, &issuer).is_err());
    for variant in 0..4 {
        let mut changed = material.clone();
        let epoch = changed.record_epoch.as_mut().unwrap();
        match variant {
            0 => epoch.community[0] ^= 1,
            1 => epoch.policy_epoch += 1,
            2 => epoch.proof_scope.circuit_digest[0] ^= 1,
            _ => epoch.proof_scope.verifying_key_digest[0] ^= 1,
        }
        assert!(changed.validate(&changed.community).is_err());
    }
    let keys: [&[u8]; 2] = [b"record-epoch-published:v1", b"record-epoch-anchor:v1"];
    let mut tx = cssr::Storage::transaction(store).unwrap();
    let original = keys.map(|key| tx.get(key).unwrap().unwrap());
    tx.rollback().unwrap();
    for variant in 0..15 {
        let index = if variant < 5 { 0 } else { 1 };
        let mut changed: Value = serde_json::from_slice(&original[index]).unwrap();
        let pointer = match variant {
            0 | 5 => None, // Missing either half cannot become legacy None.
            1 => Some("/object/0"),
            2 => Some("/descriptor/downloadDigest/0"),
            3 => Some("/descriptor/downloadBytes"),
            4 => Some("/descriptor/root/0"),
            6 => Some("/descriptor/root/0"),
            7 => Some("/period_seconds"),
            8 => Some("/frozen_at"),
            9 => Some("/configuration/0"),
            10 => Some("/extension_configuration/0"),
            11 => Some("/descriptor/policyEpoch"),
            12 => Some("/descriptor/proofScope/circuitDigest/0"),
            13 => Some("/descriptor/community/0"),
            _ => Some("/descriptor/leafCount"),
        };
        let replacement = pointer.map(|pointer| {
            let value = changed.pointer_mut(pointer).unwrap();
            *value = json!(match variant {
                7 => 0,
                8 => descriptor.expires_at,
                _ => value.as_u64().unwrap() ^ 1,
            });
            serde_json::to_vec(&changed).unwrap()
        });
        let mut tx = cssr::Storage::transaction(store).unwrap();
        match &replacement {
            Some(bytes) => tx.put(keys[index], bytes).unwrap(),
            None => tx.delete(keys[index]).unwrap(),
        }
        tx.commit().unwrap();
        assert!(
            ledger.public_verifier_material(2, 1, &issuer).is_err(),
            "corrupt publication {variant}"
        );
        let mut tx = cssr::Storage::transaction(store).unwrap();
        assert_eq!(tx.get(keys[index]).unwrap(), replacement);
        assert_eq!(
            tx.get(keys[1 - index]).unwrap().as_ref(),
            Some(&original[1 - index])
        );
        tx.put(keys[index], &original[index]).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            ledger.public_verifier_material(1, 1, &issuer).unwrap(),
            material
        );
    }
    // Agreement between stored halves cannot substitute the actual active
    // community, Policy epoch or artifact scope supplied by the owner.
    for pointer in [
        "/descriptor/community/0",
        "/descriptor/policyEpoch",
        "/descriptor/proofScope/circuitDigest/0",
        "/descriptor/proofScope/verifyingKeyDigest/0",
    ] {
        let mut tx = cssr::Storage::transaction(store).unwrap();
        for (key, bytes) in keys.iter().zip(&original) {
            let mut changed: Value = serde_json::from_slice(bytes).unwrap();
            let field = changed.pointer_mut(pointer).unwrap();
            *field = json!(field.as_u64().unwrap() ^ 1);
            tx.put(key, &serde_json::to_vec(&changed).unwrap()).unwrap();
        }
        tx.commit().unwrap();
        assert!(ledger.public_verifier_material(2, 1, &issuer).is_err());
        let mut tx = cssr::Storage::transaction(store).unwrap();
        for (key, bytes) in keys.iter().zip(&original) {
            tx.put(key, bytes).unwrap();
        }
        tx.commit().unwrap();
        assert_eq!(
            ledger.public_verifier_material(1, 1, &issuer).unwrap(),
            material
        );
    }
}
