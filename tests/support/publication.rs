//! Real signed publication from a genuinely activated extension ledger.
use cbcn::{Error, document::Cache};
use cblc::{
    accounting::AccountProofVerifier, accounting_ledger::AccountLedger,
    publication::PublicVerifierMaterial,
};
use csgn::{Kind, SecretKey, Signer};

pub fn exercise<V: AccountProofVerifier>(ledger: &mut AccountLedger<V>) -> PublicVerifierMaterial {
    let issuer = crate::common::record_fixture_issuer(ledger, 100);
    let material = ledger.public_verifier_material(1, 1, &issuer).unwrap();
    // The status publishes the recorded ring and the identity certificates bind.
    assert_eq!(
        material.community_identity,
        crate::common::CERTIFICATE_IDENTITY
    );
    assert_eq!(
        material
            .certificate_keys
            .last()
            .map(|p| p.public_key.clone()),
        Some(issuer.public_key().to_vec())
    );
    // The actual fixture configures encoded(3) as admission trust before the
    // ledger is constructed. Its economic proof policy is a separate digest.
    assert_eq!(material.admission_policy_digest, [3; 32]);
    assert_ne!(material.admission_policy_digest, material.policy_digest);
    #[cfg(feature = "schema")]
    {
        let schema =
            serde_json::to_value(<PublicVerifierMaterial as utoipa::PartialSchema>::schema())
                .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let value = serde_json::to_value(&material).unwrap();
        assert!(validator.is_valid(&value));
        let mut legacy = value.clone();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("admissionPolicyDigest");
        assert!(!validator.is_valid(&legacy));
        let mut unknown = value.clone();
        unknown["member"] = "forbidden".into();
        assert!(!validator.is_valid(&unknown));
        let mut nested = value;
        nested["policy"]["privateOpening"] = true.into();
        assert!(!validator.is_valid(&nested));
    }
    material.validate_at(&material.community, 200).unwrap();
    for now in [0, material.policy.account.policy_valid_until] {
        assert_eq!(
            material.validate_at(&material.community, now),
            Err(cblc::Error::Expired)
        );
    }
    assert_eq!(
        material.validate_at("other.example", 200),
        Err(cblc::Error::Admission)
    );
    for (revision, epoch) in [
        (0, 1),
        (czkp::MAX_INTEGER + 1, 1),
        (1, 0),
        (1, czkp::MAX_INTEGER + 1),
    ] {
        assert_eq!(
            ledger.public_verifier_material(revision, epoch, &issuer),
            Err(cblc::Error::InvalidInput)
        );
    }
    let wrong_issuer = cssr::certificate::CertificateIssuer::new(&[4; 32]).unwrap();
    assert_eq!(
        ledger.public_verifier_material(1, 1, &wrong_issuer),
        Err(cblc::Error::PolicyMismatch)
    );
    // Host files cannot replace the activated ledger's authenticated RAM snapshot.
    // Fresh authentication must independently reject a changed manifest at its
    // original pin, including a semantically equivalent JSON representation.
    let configured_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".extension-test/config.json");
    let saved_config = std::fs::read(&configured_path).unwrap();
    let mut configuration: serde_json::Value = serde_json::from_slice(&saved_config).unwrap();
    let old_directory = std::path::PathBuf::from(configuration["directory"].as_str().unwrap());
    let mut manifest = std::fs::read(old_directory.join("manifest.json")).unwrap();
    manifest.push(b' ');
    let changed_directory = tempfile::tempdir().unwrap();
    std::fs::write(changed_directory.path().join("manifest.json"), &manifest).unwrap();
    configuration["directory"] = changed_directory.path().to_str().unwrap().into();
    use sha2::Digest;
    configuration["manifestSha256"] = data_encoding::HEXLOWER
        .encode(&sha2::Sha256::digest(&manifest))
        .into();
    std::fs::write(
        &configured_path,
        serde_json::to_vec(&configuration).unwrap(),
    )
    .unwrap();
    let changed_binding = ledger.public_verifier_material(1, 1, &issuer);
    std::fs::write(&configured_path, saved_config).unwrap();
    assert_eq!(changed_binding, Ok(material.clone()));
    let circuit = std::fs::read(old_directory.join("circuits.json")).unwrap();
    let keys = std::fs::read(old_directory.join("keys.json")).unwrap();
    let srs_g1 = std::fs::read(old_directory.join("setup/g1.dat")).unwrap();
    let srs_g2 = std::fs::read(old_directory.join("setup/g2.dat")).unwrap();
    assert!(matches!(
        cblc::artifacts::ExtensionArtifacts::authenticate(cblc::artifacts::ArtifactBytes {
            manifest: &manifest,
            manifest_sha256: material.manifest_sha256,
            circuit: &circuit,
            keys: &keys,
            srs_g1: &srs_g1,
            srs_g2: &srs_g2,
        }),
        Err(cblc::Error::PolicyMismatch)
    ));
    for variant in 0..20 {
        let mut invalid = material.clone();
        match variant {
            0 => {
                invalid.community.clear();
            }
            1 => invalid.revision = 0,
            2 => invalid.revision = czkp::MAX_INTEGER + 1,
            3 => invalid.policy_epoch = 0,
            4 => invalid.policy_epoch = czkp::MAX_INTEGER + 1,
            5 => invalid.policy.max_proof_bytes = 1,
            6 => invalid.proof_scope.circuit_digest = [0; 32],
            7 => invalid.proof_scope.verifying_key_digest = [0; 32],
            8 => invalid.manifest_sha256 = [0; 32],
            9 => invalid.account_response_key = [0; 32],
            10 => invalid.certificate_keys.clear(),
            17 => invalid.community_identity = [0; 32],
            18 => {
                // A status whose ring has no open (current) key is refused.
                let open = invalid.certificate_keys.last_mut().unwrap();
                open.valid_until = Some(open.valid_from + 1);
            }
            11 => invalid.policy.max_authorization_seconds = 0,
            12 => invalid.policy.max_proof_bytes = i32::MAX as usize + 1,
            13 => invalid.policy.checkpoint_period_seconds = 0,
            14 => invalid.policy.account.maximum_available = 0,
            15 => invalid.policy_digest[0] ^= 1,
            16 => invalid.extension_policy.revision = 0,
            _ => invalid.policy.account.policy_revision = 0,
        }
        assert!(invalid.validate(&invalid.community).is_err());
    }
    let mut signer = Signer::new(
        &material.community,
        SecretKey::from_seed(&mut [31; 32]),
        100,
        1000,
    )
    .unwrap();
    let mut cache = Cache::<PublicVerifierMaterial>::default();
    let payload = serde_json::to_vec(&material).unwrap();
    let bytes = signer
        .sign(Kind::SettingsSnapshot, &payload, 100, 900)
        .unwrap();
    assert_eq!(
        cache
            .install(signer.key_ring(), bytes.clone(), 200)
            .unwrap()
            .as_ref(),
        bytes
    );
    assert_eq!(cache.current(200).unwrap().as_ref(), bytes);
    let authenticated = signer
        .key_ring()
        .verify(&bytes, Kind::SettingsSnapshot, 200)
        .unwrap();
    let installed: PublicVerifierMaterial =
        serde_json::from_slice(authenticated.payload()).unwrap();
    assert_eq!(installed, material);
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".extension-test/publication.json"),
        serde_json::to_vec(&serde_json::json!({
            "signed": bytes,
            "configuredFixtureRing": signer.key_ring().to_cbor(),
            "material": installed,
        }))
        .unwrap(),
    )
    .unwrap();

    // The configured publication ring is independent of the submitted document.
    let mut stranger = Signer::new(
        &material.community,
        SecretKey::from_seed(&mut [32; 32]),
        100,
        1000,
    )
    .unwrap();
    let other = stranger
        .sign(Kind::SettingsSnapshot, &payload, 100, 900)
        .unwrap();
    assert_eq!(
        cache.install(signer.key_ring(), other, 200),
        Err(Error::Signature)
    );
    let other_kind = signer.sign(Kind::Credential, &payload, 100, 900).unwrap();
    assert_eq!(
        cache.install(signer.key_ring(), other_kind, 200),
        Err(Error::Signature)
    );
    for variant in 0..8 {
        let mut value = serde_json::to_value(&material).unwrap();
        match variant {
            0 => value["purpose"] = "cblc.record-certificate.v1".into(),
            1 => value["community"] = "other.example".into(),
            2 => value["revision"] = 0.into(),
            3 => value["policyEpoch"] = 0.into(),
            4 => value["policyDigest"][0] = (value["policyDigest"][0].as_u64().unwrap() ^ 1).into(),
            5 => value["purpose"] = "cblc.public-verifier.v1".into(),
            6 => {
                value
                    .as_object_mut()
                    .unwrap()
                    .remove("admissionPolicyDigest");
            }
            _ => value["admissionPolicyDigest"] = serde_json::json!([3]),
        }
        let changed = signer
            .sign(
                Kind::SettingsSnapshot,
                &serde_json::to_vec(&value).unwrap(),
                100,
                900,
            )
            .unwrap();
        assert_eq!(
            cache.install(signer.key_ring(), changed, 200),
            Err(Error::Incoherent)
        );
    }
    for change_admission in [false, true] {
        let mut changed = material.clone();
        if change_admission {
            changed.admission_policy_digest[0] ^= 1;
        } else {
            changed.account_response_key[0] ^= 1;
        }
        let candidate = signer
            .sign(
                Kind::SettingsSnapshot,
                &serde_json::to_vec(&changed).unwrap(),
                100,
                900,
            )
            .unwrap();
        assert_eq!(
            cache.install(signer.key_ring(), candidate, 200),
            Err(Error::Equivocation)
        );
    }
    let mut newer = material.clone();
    newer.revision = 2;
    newer.policy_epoch = 2;
    let candidate = signer
        .sign(
            Kind::SettingsSnapshot,
            &serde_json::to_vec(&newer).unwrap(),
            101,
            900,
        )
        .unwrap();
    cache.install(signer.key_ring(), candidate, 200).unwrap();
    for (revision, epoch) in [(1, 2), (2, 1)] {
        let mut stale = newer.clone();
        stale.revision = revision;
        stale.policy_epoch = epoch;
        let bytes = signer
            .sign(
                Kind::SettingsSnapshot,
                &serde_json::to_vec(&stale).unwrap(),
                101,
                900,
            )
            .unwrap();
        assert_eq!(
            cache.install(signer.key_ring(), bytes, 200),
            Err(Error::Rollback)
        );
    }
    assert_eq!(cache.current(199), Err(Error::ClockRegression));
    assert_eq!(cache.current(900), Err(Error::Expired));
    installed
}

/// Use only material recovered from the independently configured signature ring.
/// This checks cryptographic binding, not the unresolved member-currentness claim.
pub fn verify_record(
    material: &PublicVerifierMaterial,
    record: &cblc::extensions::PublicRecord,
    proof: &[u8],
) {
    use cblc::extensions::ExtensionVerifier;
    use sha2::{Digest, Sha256};
    material
        .validate_at(&material.community, record.context.expires_at - 1)
        .unwrap();
    assert_eq!(
        record.community,
        <[u8; 32]>::from(Sha256::digest(material.community.as_bytes()))
    );
    let directory = crate::common::native::extension_directory();
    let artifacts =
        crate::common::native::extension_pinned(&directory, material.manifest_sha256).unwrap();
    assert_eq!(artifacts.scope(), material.proof_scope);
    let options = crate::common::native::options(material.policy.max_proof_bytes);
    let verifier = cblc::verification::NativeExtensionVerifier::new(
        options.clone(),
        options.clone(),
        artifacts,
    )
    .unwrap();
    let statement = cblc::extensions::ExtensionStatement::Record {
        policy: material.extension_policy.clone(),
        record: record.clone(),
    };
    verifier.verify_anonymous(&statement, proof).unwrap();
    let mut wrong_context = record.clone();
    wrong_context.context.challenge[0] ^= 1;
    assert_eq!(
        verifier.verify_anonymous(
            &cblc::extensions::ExtensionStatement::Record {
                policy: material.extension_policy.clone(),
                record: wrong_context,
            },
            proof
        ),
        Err(cblc::Error::CryptoProvider)
    );
    assert!(matches!(
        crate::common::native::extension_pinned(&directory, [0; 32]),
        Err(cblc::Error::PolicyMismatch)
    ));

    // Authenticate a complete host-read copy first. Later file mutation must
    // refuse new snapshots and cannot change the already authenticated RAM data.
    let temporary = tempfile::tempdir().unwrap();
    let copied = temporary.path().join("artifacts");
    std::fs::create_dir_all(copied.join("setup")).unwrap();
    for name in [
        "manifest.json",
        "circuits.json",
        "keys.json",
        "setup/g1.dat",
        "setup/g2.dat",
    ] {
        std::fs::copy(directory.join(name), copied.join(name)).unwrap();
    }
    let copied_artifacts =
        crate::common::native::extension_pinned(&copied, material.manifest_sha256).unwrap();
    let copied_verifier = cblc::verification::NativeExtensionVerifier::new(
        options.clone(),
        options,
        copied_artifacts,
    )
    .unwrap();
    copied_verifier.verify_anonymous(&statement, proof).unwrap();
    for name in ["circuits.json", "keys.json"] {
        let path = copied.join(name);
        let original = std::fs::read(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["unrecognizedFixtureField"] = true.into();
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            crate::common::native::extension_pinned(&copied, material.manifest_sha256),
            Err(cblc::Error::PolicyMismatch)
        ));
        copied_verifier.verify_anonymous(&statement, proof).unwrap();
        std::fs::write(&path, original).unwrap();
    }
}
