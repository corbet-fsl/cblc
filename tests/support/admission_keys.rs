//! Original signer continuity on the same genuine native activation and SQL owner.
use super::*;
use cblc::accounting_ledger::AdmissionKeyState;

fn rotate(signer: &mut csgn::Signer, seed: u8, now: u64) -> Vec<u8> {
    let proof = signer
        .rotate_with_proof(csgn::SecretKey::from_seed(&mut [seed; 32]), now, 1000)
        .unwrap();
    signer
        .acknowledge_transition(signer.ring_revision())
        .unwrap();
    proof
}

fn install(
    path: &Path,
    authority: (cblc::admission::AdmissionTrust, u64),
    settings: &AccountLedgerPolicy,
    extension: &ExtensionPolicy,
    scope: &AccountProofScope,
    directory: &Path,
    init: &Value,
) -> Result<AccountLedger<RealVerifier>, Error> {
    let (trust, revision) = authority;
    let keys = AdmissionKeyState {
        revision,
        policy_keys: trust.policy_keys.clone(),
    };
    common::host_storage::open_with_admission_keys(
        path,
        trust,
        settings.clone(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
        keys,
    )?
    .with_extensions(
        extension.clone(),
        verifier(scope.clone(), directory),
        limits(),
        activation(init),
    )
}

pub(super) fn exercise(
    fixture: &Fixture,
    settings: &AccountLedgerPolicy,
    extension: &ExtensionPolicy,
    scope: &AccountProofScope,
    directory: &Path,
    init: &Value,
) {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("signer-continuity.db");
    let mut signer = csgn::Signer::new(
        "community.example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        1,
        100_000,
    )
    .unwrap();
    rotate(&mut signer, 4, 90);
    rotate(&mut signer, 5, 95);
    let mut trust = fixture.trust.clone();
    trust.policy_keys = signer.key_ring().clone();
    let original_trust = trust.clone();
    // The genuine independently configured signer already has two transitions
    // before first activation. No floor is inferred from its public ring bytes.
    let mut ledger = install(
        &path,
        (trust.clone(), 2),
        settings,
        extension,
        scope,
        directory,
        init,
    )
    .unwrap();
    let original_anchor = anchor(&path);
    let mut stale = install(
        &path,
        (trust.clone(), 2),
        settings,
        extension,
        scope,
        directory,
        init,
    )
    .unwrap();
    assert_eq!(ledger.admission_key_state().unwrap().revision, 2);
    let tuned = ledger
        .update_waiting_period(0, settings.account.abandon_after + 10, || 110)
        .unwrap();
    let proof = rotate(&mut signer, 6, 120);
    let retained = inspection::Connection::open(&path).unwrap().snapshot();
    assert!(ledger.advance_admission_keys(2, &proof, || 119).is_err());
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
    assert!(ledger.advance_admission_keys(1, &proof, || 120).is_err());
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
    let mut damaged = proof.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(ledger.advance_admission_keys(2, &damaged, || 120).is_err());
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
    let current = ledger.advance_admission_keys(2, &proof, || 120).unwrap();
    assert_eq!(current.revision, 3);
    assert_eq!(current.policy_keys, *signer.key_ring());
    assert_eq!(
        ledger.advance_admission_keys(2, &proof, || 121).unwrap(),
        current
    );
    assert_eq!(anchor(&path), original_anchor);
    assert!(matches!(
        stale.update_waiting_period(0, 120, || 121),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(stale.reload_policy().unwrap(), tuned);
    assert_eq!(stale.admission_key_state().unwrap(), current);
    trust.policy_keys = signer.key_ring().clone();
    drop(stale);
    drop(ledger);
    assert!(
        install(
            &path,
            (original_trust, 2),
            settings,
            extension,
            scope,
            directory,
            init,
        )
        .is_err()
    );
    let mut reopened = install(
        &path,
        (trust.clone(), 3),
        settings,
        extension,
        scope,
        directory,
        init,
    )
    .unwrap();
    assert_eq!(reopened.waiting_period().unwrap(), tuned);
    assert_eq!(reopened.admission_key_state().unwrap(), current);
    assert_eq!(anchor(&path), original_anchor);
    #[cfg(feature = "publication")]
    {
        let material = reopened
            .public_verifier_material(
                1,
                1,
                &cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap(),
            )
            .unwrap();
        assert_eq!(material.admission_policy_digest, [3; 32]);
        assert_eq!(material.policy_digest, tuned.policy_digest);
    }
    // A late return is uncertain, not rollback. Reload reconciles that same
    // committed successor; no fresh ledger or modified genesis proof is used.
    let next = rotate(&mut signer, 7, 130);
    let samples = Cell::new(0);
    assert!(matches!(
        reopened.advance_admission_keys(3, &next, || {
            let sample = samples.get();
            samples.set(sample + 1);
            if sample < 3 { 130 } else { 1000 }
        }),
        Err(Error::Storage)
    ));
    assert_eq!(samples.get(), 4);
    reopened.reload_policy().unwrap();
    assert_eq!(reopened.admission_key_state().unwrap().revision, 4);
    assert_eq!(anchor(&path), original_anchor);
    // Fourth-sample failures belong to the shared transaction's post-success
    // check; fifth-sample failures belong to this method's final exposure cut.
    for (seed, now, returned, cut) in [
        (8, 1001, 0, 3),
        (9, 1002, 1001, 3),
        (10, 1003, 0, 4),
        (11, 1004, 1003, 4),
        (12, 1005, 2000, 4),
    ] {
        let revision = signer.ring_revision();
        let proof = signer
            .rotate_with_proof(csgn::SecretKey::from_seed(&mut [seed; 32]), now, 2000)
            .unwrap();
        signer
            .acknowledge_transition(signer.ring_revision())
            .unwrap();
        let samples = Cell::new(0);
        assert!(matches!(
            reopened.advance_admission_keys(revision, &proof, || {
                let sample = samples.get();
                samples.set(sample + 1);
                if sample < cut { now } else { returned }
            }),
            Err(Error::Storage)
        ));
        assert_eq!(samples.get(), cut + 1);
        reopened.reload_policy().unwrap();
        assert_eq!(
            reopened.admission_key_state().unwrap().revision,
            revision + 1
        );
        assert_eq!(anchor(&path), original_anchor);
    }
    trust.policy_keys = signer.key_ring().clone();
    drop(reopened);
    drop(
        install(
            &path,
            (trust.clone(), 9),
            settings,
            extension,
            scope,
            directory,
            init,
        )
        .unwrap(),
    );
    let mut store = cssr::LibsqlStore::local(&path, "community.example").unwrap();
    let mut tx = cssr::Storage::transaction(&mut store).unwrap();
    let history_key = b"admission-key-history:v1";
    let original = tx.get(history_key).unwrap().unwrap();
    let mut truncated: Value = serde_json::from_slice(&original).unwrap();
    truncated["transitions"].as_array_mut().unwrap().pop();
    tx.put(history_key, &serde_json::to_vec(&truncated).unwrap())
        .unwrap();
    tx.commit().unwrap();
    let retained = inspection::Connection::open(&path).unwrap().snapshot();
    assert!(
        install(
            &path,
            (trust.clone(), 9),
            settings,
            extension,
            scope,
            directory,
            init,
        )
        .is_err()
    );
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
    let mut tx = cssr::Storage::transaction(&mut store).unwrap();
    tx.put(history_key, &original).unwrap();
    tx.delete(b"admission-key-bootstrap:v1").unwrap();
    tx.commit().unwrap();
    let retained = inspection::Connection::open(&path).unwrap().snapshot();
    assert!(
        install(
            &path,
            (trust.clone(), 9),
            settings,
            extension,
            scope,
            directory,
            init,
        )
        .is_err()
    );
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
    let mut tx = cssr::Storage::transaction(&mut store).unwrap();
    tx.delete(history_key).unwrap();
    tx.commit().unwrap();
    let retained = inspection::Connection::open(&path).unwrap().snapshot();
    assert!(matches!(
        install(
            &path,
            (trust, 9),
            settings,
            extension,
            scope,
            directory,
            init
        ),
        Err(Error::UnsupportedCapability)
    ));
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
}
