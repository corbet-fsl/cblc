//! Real signed publication from a genuinely activated extension ledger.
use cbcn::{Error, document::Cache};
use cblc::{
    accounting::AccountProofVerifier, accounting_ledger::AccountLedger,
    publication::PublicVerifierMaterial,
};
use csgn::{Kind, SecretKey, Signer};

pub fn exercise<V: AccountProofVerifier>(ledger: &mut AccountLedger<V>) -> PublicVerifierMaterial {
    let issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    let material = ledger.public_verifier_material(1, 1, &issuer).unwrap();
    #[cfg(feature = "schema")]
    {
        let schema =
            serde_json::to_value(<PublicVerifierMaterial as utoipa::PartialSchema>::schema())
                .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let value = serde_json::to_value(&material).unwrap();
        assert!(validator.is_valid(&value));
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
    // Changing even semantically equivalent manifest bytes after real activation
    // cannot silently replace the producer's authenticated artifact binding.
    let configured_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".extension-test/config.json");
    let saved_config = std::fs::read(&configured_path).unwrap();
    let mut configuration: serde_json::Value = serde_json::from_slice(&saved_config).unwrap();
    let old_directory = std::path::Path::new(configuration["directory"].as_str().unwrap());
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
    assert_eq!(changed_binding, Err(cblc::Error::PolicyMismatch));
    for variant in 0..18 {
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
            10 => invalid.certificate_key.clear(),
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
    for variant in 0..5 {
        let mut value = serde_json::to_value(&material).unwrap();
        match variant {
            0 => value["purpose"] = "cblc.record-certificate.v1".into(),
            1 => value["community"] = "other.example".into(),
            2 => value["revision"] = 0.into(),
            3 => value["policyEpoch"] = 0.into(),
            _ => value["policyDigest"][0] = (value["policyDigest"][0].as_u64().unwrap() ^ 1).into(),
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
    let mut changed = material.clone();
    changed.account_response_key[0] ^= 1;
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
    use sha2::{Digest, Sha256};
    use std::{path::PathBuf, time::Duration};
    material
        .validate_at(&material.community, record.context.expires_at - 1)
        .unwrap();
    assert_eq!(
        record.community,
        <[u8; 32]>::from(Sha256::digest(material.community.as_bytes()))
    );
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".extension-test");
    let temporary = tempfile::tempdir().unwrap();
    let config_path = temporary.path().join("verified-config.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "directory": directory,
            "manifestSha256": data_encoding::HEXLOWER.encode(&material.manifest_sha256),
        }))
        .unwrap(),
    )
    .unwrap();
    let config = cvfy::ProcessVerifierConfig {
        node: std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("node"))
            .find(|p| p.is_absolute() && p.is_file())
            .unwrap(),
        script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("runtime/extensions/node-verifier.mjs"),
        artifact_config: config_path.clone(),
        scope: material.proof_scope.clone(),
        timeout: Duration::from_secs(180),
        maximum_parallel: 1,
        max_proof_bytes: material.policy.max_proof_bytes,
        node_heap_megabytes: 4096,
    };
    let verifier = cvfy::ProcessVerifier::new(config).unwrap();
    let statement = cblc::extensions::ExtensionStatement::Record {
        policy: material.extension_policy.clone(),
        record: record.clone(),
    };
    verifier.verify(&statement, proof).unwrap();
    let mut wrong_context = record.clone();
    wrong_context.context.challenge[0] ^= 1;
    assert_eq!(
        verifier.verify(
            &cblc::extensions::ExtensionStatement::Record {
                policy: material.extension_policy.clone(),
                record: wrong_context,
            },
            proof
        ),
        Err(cblc::Error::CryptoProvider)
    );
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "directory": directory,
            "manifestSha256": "00".repeat(32),
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        verifier.verify(&statement, proof),
        Err(cblc::Error::CryptoProvider)
    );
    // A complete copied fixture must first verify successfully, so later
    // refusals cannot be caused merely by absent setup or key files.
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
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "directory": copied,
            "manifestSha256": data_encoding::HEXLOWER.encode(&material.manifest_sha256),
        }))
        .unwrap(),
    )
    .unwrap();
    verifier.verify(&statement, proof).unwrap();
    for name in ["circuits.json", "keys.json"] {
        let path = copied.join(name);
        let original = std::fs::read(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        // The extra group field is ignored by proof selection; the authenticated
        // group hash must nevertheless refuse it.
        value["unrecognizedFixtureField"] = true.into();
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let refused = verifier.verify(&statement, proof);
        std::fs::write(&path, original).unwrap();
        assert_eq!(refused, Err(cblc::Error::CryptoProvider));
    }
}
