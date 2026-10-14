//! Real signed publication and retained-floor tests. These exercise the view
//! boundary only; none construct a VerifiedRecord or substitute native proof.
use super::*;
use crate::{accounting::AccountPolicy, accounting_ledger::AccountLedgerPolicy};
use csgn::{Kind, SecretKey, Signer};

fn material() -> PublicVerifierMaterial {
    let community = "community-example";
    let account = AccountPolicy {
        initial_credit: 3,
        maximum_available: 4,
        outgoing_reservation: 1,
        incoming_reservation: 1,
        policy_revision: 1,
        policy_valid_from: 1,
        policy_valid_until: 2000,
        newcomer_period: 100,
        rate_window: 20,
        newcomer_admissions: 2,
        maximum_admissions: 4,
        refill_period: 100,
        refill_units: 1,
        abandon_after: 1000,
    };
    let community_hash = Sha256::digest(community.as_bytes()).into();
    let scope = AccountProofScope {
        circuit_digest: [1; 32],
        verifying_key_digest: [2; 32],
    };
    let policy_digest = account.digest(&community_hash).unwrap();
    PublicVerifierMaterial {
        purpose: crate::publication::Purpose::PublicVerifierV2,
        community: community.into(),
        revision: 1,
        policy_epoch: 1,
        policy: AccountLedgerPolicy {
            account,
            max_authorization_seconds: 100,
            max_proof_bytes: crate::extensions::EXTENSION_PROOF_BYTES,
            checkpoint_period_seconds: 100,
        },
        policy_digest,
        admission_policy_digest: [3; 32],
        extension_policy: crate::extensions::ExtensionPolicy {
            revision: 1,
            public_record_quorum: 10,
            change_token_cost: 1,
            deposit_delay_seconds: 1,
            minimum_deposit_batch: 2,
            standing_policy_digest: [9; 32],
        },
        proof_scope: scope.clone(),
        manifest_sha256: [3; 32],
        account_response_key: [4; 32],
        certificate_key: cssr::certificate::CertificateIssuer::new(&[3; 32])
            .unwrap()
            .public_key()
            .to_vec(),
        settlement: None,
        wave_verifier: None,
        record_epoch: Some(Epoch {
            purpose: czkp::record::Purpose::RecordEpochV3,
            community: community_hash,
            policy_epoch: 1,
            epoch: 1,
            starts_at: 100,
            expires_at: 200,
            root: [5; 32],
            issuer_key: [6; 32],
            proof_scope: scope,
            leaf_count: 4,
            download_digest: [7; 32],
            download_bytes: 1000,
        }),
    }
}
fn signer() -> Signer {
    Signer::new(
        "community-example",
        SecretKey::from_seed(&mut [31; 32]),
        1,
        2000,
    )
    .unwrap()
}
fn signed(signer: &mut Signer, material: &PublicVerifierMaterial, deadline: u64) -> Balance {
    let bytes = signer
        .sign(
            Kind::SettingsSnapshot,
            &serde_json::to_vec(material).unwrap(),
            100,
            deadline,
        )
        .unwrap();
    Balance::verify(
        signer.key_ring(),
        &bytes,
        material.policy_epoch,
        material.revision,
        110,
    )
    .unwrap()
}
fn view(material: &PublicVerifierMaterial) -> View {
    View {
        community: material.community.clone(),
        period_seconds: 100,
        scope: material.proof_scope.clone(),
        artifacts: ArtifactBinding {
            manifest_sha256: material.manifest_sha256,
            certificate_key: material.certificate_key.as_slice().try_into().unwrap(),
        },
        observed_time: 0,
        policy_epoch: 0,
        balance: None,
        epoch: None,
    }
}
fn bounds() -> CharterBounds {
    CharterBounds {
        policy_epoch: 1,
        valid_until: 500,
    }
}

#[test]
fn real_signed_publication_requires_trusted_period_epoch_community_and_native_pins() {
    let original = material();
    let balance = signed(&mut signer(), &original, 900);
    assert_eq!(
        view(&original).observe(&balance, bounds(), 110),
        Ok(original.clone())
    );
    for variant in 0..5 {
        let mut verifier_view = view(&original);
        match variant {
            0 => verifier_view.period_seconds = 50,
            1 => verifier_view.community = "other.example".into(),
            2 => verifier_view.scope.circuit_digest[0] ^= 1,
            3 => verifier_view.artifacts.manifest_sha256[0] ^= 1,
            _ => verifier_view.artifacts.certificate_key[0] ^= 1,
        }
        assert!(verifier_view.observe(&balance, bounds(), 110).is_err());
    }
    assert_eq!(
        view(&original).observe(
            &balance,
            CharterBounds {
                policy_epoch: 2,
                ..bounds()
            },
            110
        ),
        Err(Error::PolicyMismatch)
    );
    for invalid in [
        CharterBounds {
            policy_epoch: 0,
            ..bounds()
        },
        CharterBounds {
            valid_until: czkp::MAX_INTEGER + 1,
            ..bounds()
        },
    ] {
        assert_eq!(
            view(&original).observe(&balance, invalid, 110),
            Err(Error::InvalidInput)
        );
    }
    // The publication owner signature is real and cannot be replaced by a key
    // supplied with member input, even if all decoded fields would match.
    let trusted = signer();
    let mut stranger = Signer::new(
        "community-example",
        SecretKey::from_seed(&mut [32; 32]),
        1,
        2000,
    )
    .unwrap();
    let bytes = stranger
        .sign(
            Kind::SettingsSnapshot,
            &serde_json::to_vec(&original).unwrap(),
            100,
            900,
        )
        .unwrap();
    assert!(matches!(
        Balance::verify(trusted.key_ring(), &bytes, 1, 1, 110),
        Err(cbcn::Error::Signature)
    ));
}

#[test]
fn withdrawal_preserves_balance_and_policy_floors_without_granting_epoch_authority() {
    let original = material();
    let mut signer = signer();
    let old = signed(&mut signer, &original, 900);
    let mut current = view(&original);
    current.observe(&old, bounds(), 110).unwrap();
    let mut withdrawn = original.clone();
    withdrawn.revision = 2;
    withdrawn.policy_epoch = 2;
    withdrawn.record_epoch = None;
    let withdrawn = signed(&mut signer, &withdrawn, 900);
    assert_eq!(
        current.observe(
            &withdrawn,
            CharterBounds {
                policy_epoch: 2,
                ..bounds()
            },
            110
        ),
        Err(Error::UnsupportedCapability)
    );
    assert_eq!(current.observe(&old, bounds(), 110), Err(Error::Replay));
    let mut rolled_back = original.clone();
    rolled_back.revision = 3;
    let rolled_back = signed(&mut signer, &rolled_back, 900);
    assert_eq!(
        current.observe(&rolled_back, bounds(), 110),
        Err(Error::Replay)
    );
}

#[test]
fn current_signed_balance_reendorses_exact_frozen_epoch_without_changing_provenance() {
    let original = material();
    let mut signer = signer();
    let old = signed(&mut signer, &original, 900);
    let mut current = view(&original);
    current.observe(&old, bounds(), 110).unwrap();
    let frozen = serde_json::to_vec(original.record_epoch.as_ref().unwrap()).unwrap();
    let mut newer = original.clone();
    newer.policy_epoch = 2;
    newer.revision = 2;
    let publication = signed(&mut signer, &newer, 180);
    let charter = CharterBounds {
        policy_epoch: 2,
        ..bounds()
    };
    assert_eq!(
        current.observe(&publication, charter, 110),
        Ok(newer.clone())
    );
    assert_eq!(
        serde_json::to_vec(current.epoch.as_ref().unwrap()).unwrap(),
        frozen
    );
    assert_eq!(
        view(&original).observe(&old, charter, 110),
        Err(Error::PolicyMismatch)
    );
    assert_eq!(current.observe(&old, bounds(), 110), Err(Error::Replay));
    assert_eq!(
        current.observe(&publication, charter, 180),
        Err(Error::Expired)
    );

    for policy_epoch in [0, 3, czkp::MAX_INTEGER + 1] {
        let mut invalid = newer.clone();
        invalid.record_epoch.as_mut().unwrap().policy_epoch = policy_epoch;
        assert!(invalid.validate(&invalid.community).is_err());
        let authenticated = signed(&mut signer, &invalid, 180);
        assert!(
            view(&original)
                .observe(&authenticated, charter, 110)
                .is_err()
        );
    }
    let mut changed = newer;
    changed.revision = 3;
    changed.record_epoch.as_mut().unwrap().policy_epoch = 2;
    let changed = signed(&mut signer, &changed, 180);
    assert_eq!(
        current.observe(&changed, charter, 110),
        Err(Error::PolicyMismatch)
    );
}

#[test]
fn signed_new_revision_cannot_replace_the_same_epoch_or_roll_back_a_newer_epoch() {
    let original = material();
    let mut signer = signer();
    let old = signed(&mut signer, &original, 900);
    let mut current = view(&original);
    current.observe(&old, bounds(), 110).unwrap();
    let mut changed = original.clone();
    changed.revision = 2;
    changed.record_epoch.as_mut().unwrap().root[0] ^= 1;
    let changed = signed(&mut signer, &changed, 900);
    assert_eq!(
        current.observe(&changed, bounds(), 110),
        Err(Error::PolicyMismatch)
    );
    assert_eq!(current.observe(&old, bounds(), 110), Err(Error::Replay));
    let mut next = original.clone();
    next.revision = 3;
    let epoch = next.record_epoch.as_mut().unwrap();
    epoch.epoch = 2;
    epoch.starts_at = 200;
    epoch.expires_at = 300;
    let next = signed(&mut signer, &next, 900);
    current.observe(&next, bounds(), 210).unwrap();
    let mut rollback = original;
    rollback.revision = 4;
    let rollback = signed(&mut signer, &rollback, 900);
    assert_eq!(
        current.observe(&rollback, bounds(), 210),
        Err(Error::Replay)
    );
}

#[test]
fn same_revision_equivocation_and_all_exclusive_lifetimes_refuse() {
    let original = material();
    let mut signer = signer();
    let balance = signed(&mut signer, &original, 900);
    let mut current = view(&original);
    current.observe(&balance, bounds(), 110).unwrap();
    let mut changed = original.clone();
    changed.account_response_key[0] ^= 1;
    let changed = signed(&mut signer, &changed, 900);
    assert_eq!(current.observe(&changed, bounds(), 110), Err(Error::Replay));
    assert_eq!(
        current.observe(&balance, bounds(), 99),
        Err(Error::ClockRollback)
    );
    assert_eq!(
        current.observe(&balance, bounds(), 200),
        Err(Error::Expired)
    );
    assert_eq!(
        current.observe(
            &balance,
            CharterBounds {
                valid_until: 110,
                ..bounds()
            },
            110
        ),
        Err(Error::Expired)
    );
    let expired = signed(&mut signer, &original, 150);
    assert_eq!(
        current.observe(&expired, bounds(), 150),
        Err(Error::Expired)
    );
}

#[test]
fn observed_clock_retains_refused_late_observations_and_does_not_truncate_to_rate_window() {
    let original = material();
    let balance = signed(&mut signer(), &original, 900);
    let mut current = view(&original);
    assert_eq!(current.observe_time(110), Ok(110));
    assert_eq!(current.observe_time(200), Ok(200));
    assert_eq!(
        current.observe(&balance, bounds(), 200),
        Err(Error::Expired)
    );
    assert_eq!(current.observe_time(199), Err(Error::ClockRollback));
    for bad in [0, czkp::MAX_INTEGER + 1] {
        assert_eq!(current.observe_time(bad), Err(Error::ClockRollback));
    }
    let epoch = original.record_epoch.as_ref().unwrap();
    assert_eq!(original.policy.account.proof_valid_until(110), Ok(120));
    assert_eq!(authority_until(&balance, bounds(), &original, epoch), 200);
    assert_eq!(
        authority_until(
            &balance,
            CharterBounds {
                valid_until: 130,
                ..bounds()
            },
            &original,
            epoch
        ),
        130
    );
}

#[test]
fn wave_policy_is_derived_from_the_published_material_and_any_flip_is_refused() {
    let mut published = material();
    let derived = published.wave_policy().unwrap();
    let community: [u8; 32] = Sha256::digest(published.community.as_bytes()).into();
    assert_eq!(derived.community, community);
    assert_eq!(derived.extension, published.extension_policy);
    assert_eq!(derived.proof_scope, published.proof_scope);
    assert_eq!(derived.certificate_key, published.certificate_key);
    assert_eq!(
        derived.state_policy,
        published.policy.account.state_digest(&community).unwrap()
    );
    assert_eq!(
        (derived.valid_from, derived.valid_until),
        (1, 2000),
        "the account policy window"
    );
    published.wave_verifier = Some(derived.clone());
    published.validate(&published.community.clone()).unwrap();
    // The descriptor is published JSON in the cwlt `waveVerifier` shape.
    let json = serde_json::to_value(&published).unwrap();
    assert!(json["waveVerifier"]["statePolicy"].is_array());
    for flip in [
        |d: &mut crate::publication::WaveVerifierDescriptor| d.community[0] ^= 1,
        |d: &mut crate::publication::WaveVerifierDescriptor| d.state_policy[0] ^= 1,
        |d: &mut crate::publication::WaveVerifierDescriptor| d.proof_scope.circuit_digest[0] ^= 1,
        |d: &mut crate::publication::WaveVerifierDescriptor| {
            d.proof_scope.verifying_key_digest[0] ^= 1
        },
        |d: &mut crate::publication::WaveVerifierDescriptor| d.certificate_key[0] ^= 1,
        |d: &mut crate::publication::WaveVerifierDescriptor| d.valid_until += 1,
    ] {
        let mut forged = published.clone();
        flip(forged.wave_verifier.as_mut().unwrap());
        assert_eq!(
            forged.validate(&forged.community.clone()),
            Err(Error::PolicyMismatch)
        );
    }
}
