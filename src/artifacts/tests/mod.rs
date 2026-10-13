//! Metadata authentication tests. Synthetic bytes are never called valid proofs
//! or passed to a substitute cryptographic verifier.
use super::*;
use serde_json::{Value, json};

struct Fixture {
    manifest: Value,
    circuit: Vec<u8>,
    keys: Vec<u8>,
    g1: Vec<u8>,
    g2: Vec<u8>,
}
fn hash(bytes: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(bytes))
}
impl Fixture {
    fn new(extension: bool) -> Self {
        let circuit = b"{\"publicMetadataOnly\":true}".to_vec();
        let keys = if extension {
            br#"{"update":"0102","deposit":"0304","record":"0506"}"#.to_vec()
        } else {
            vec![1, 2]
        };
        let g1 = vec![7; 4 * 1024 * 1024];
        let g2 = vec![8; 128];
        let manifest = json!({"version":1,"compiler":"1.0.0-beta.26","backend":"5.2.1",
            "verifierTarget":"noir-recursive","accountingMode":if extension {"account-extension-v1"} else {"account-state-v2"},
            "hashScheme":"poseidon2-bn254-fixed-128-v1","numPoints":131072,
            "circuitSha256":hash(&circuit),"vkSha256":hash(&keys),"issuerKey":vec![9;64],
            "setup":[{"name":"g1.dat","bytes":g1.len(),"sha256":hash(&g1)},
                {"name":"g2.dat","bytes":g2.len(),"sha256":hash(&g2)}]});
        Self {
            manifest,
            circuit,
            keys,
            g1,
            g2,
        }
    }
    fn with<T>(&self, f: impl FnOnce(ArtifactBytes<'_>) -> T) -> T {
        let manifest = serde_json::to_vec(&self.manifest).unwrap();
        f(ArtifactBytes {
            manifest: &manifest,
            manifest_sha256: Sha256::digest(&manifest).into(),
            circuit: &self.circuit,
            keys: &self.keys,
            srs_g1: &self.g1,
            srs_g2: &self.g2,
        })
    }
    fn extension(&self) -> Result<ExtensionArtifacts, Error> {
        self.with(ExtensionArtifacts::authenticate)
    }
}
fn options() -> NativeVerifierOptions {
    NativeVerifierOptions {
        executable: "/host/czkp-bb-worker".into(),
        timeout: Duration::from_secs(30),
        maximum_parallel: 2,
        max_proof_bytes: 1024 * 1024,
        threads: 1,
        memory_megabytes: 8192,
    }
}

#[test]
fn concrete_backend_labels_require_a_separate_authenticated_manifest() {
    let mut fixture = Fixture::new(true);
    let original = serde_json::to_vec(&fixture.manifest).unwrap();
    let original_pin: [u8; 32] = Sha256::digest(&original).into();
    fixture.manifest["backend"] = json!("5.2.2");
    let changed = serde_json::to_vec(&fixture.manifest).unwrap();
    assert!(matches!(
        ExtensionArtifacts::authenticate(ArtifactBytes {
            manifest: &changed,
            manifest_sha256: original_pin,
            circuit: &fixture.circuit,
            keys: &fixture.keys,
            srs_g1: &fixture.g1,
            srs_g2: &fixture.g2,
        }),
        Err(Error::PolicyMismatch)
    ));
    fixture.manifest["backend"] = json!("5.2.1");
    // Metadata authentication only; these synthetic points are never a proof.
    assert!(fixture.extension().is_ok());
    fixture.keys[0] ^= 1;
    assert!(fixture.extension().is_err());
    fixture.keys[0] ^= 1;
    // One prover version: the retired 5.0.0 key group and any other label are refused
    // even when the manifest is independently pinned.
    for label in ["5.2.2", "5.0.0"] {
        fixture.manifest["backend"] = json!(label);
        assert!(fixture.extension().is_err());
    }
}

#[test]
fn authenticated_snapshots_bind_group_and_each_native_key_without_host_files() {
    let mut f = Fixture::new(true);
    let artifacts = f.extension().unwrap();
    let scope = artifacts.scope();
    assert_eq!(
        scope.circuit_digest,
        <[u8; 32]>::from(Sha256::digest(&f.circuit))
    );
    assert_eq!(
        scope.verifying_key_digest,
        <[u8; 32]>::from(Sha256::digest(&f.keys))
    );
    assert_eq!(artifacts.issuer, [9; 64]);
    let pin = artifacts.manifest_sha256();
    #[cfg(feature = "publication")]
    assert_eq!(
        artifacts.binding(),
        ArtifactBinding {
            manifest_sha256: pin,
            certificate_key: [9; 64]
        }
    );
    f.g1[0] ^= 1;
    f.keys[0] ^= 1;
    f.manifest["issuerKey"] = json!(vec![4; 64]);
    let configs = artifacts.configs(options(), options());
    for (config, (key, inputs)) in
        configs
            .into_iter()
            .zip([(vec![1, 2], 377), (vec![3, 4], 294), (vec![5, 6], 204)])
    {
        assert_eq!(config.verification_key, key);
        assert_eq!(config.max_public_inputs, inputs);
        assert_eq!(config.scope.circuit_digest, scope.circuit_digest);
        assert_eq!(
            config.scope.verifying_key_digest,
            <[u8; 32]>::from(Sha256::digest(&key))
        );
        assert_eq!(config.srs_g1, vec![7; 4 * 1024 * 1024]);
        assert_eq!(config.srs_g2, [8; 128]);
        assert_eq!(config.memory_megabytes, 8192);
    }
    assert_eq!(artifacts.manifest_sha256(), pin);
    assert!(f.extension().is_err());
    let f = Fixture::new(false);
    let account = f.with(AccountArtifacts::authenticate).unwrap();
    assert_eq!(
        account.scope().verifying_key_digest,
        <[u8; 32]>::from(Sha256::digest(&f.keys))
    );
    assert_eq!(account.config(options()).max_public_inputs, 243);
}

#[test]
fn changed_bytes_never_satisfy_the_independent_manifest_pin() {
    let f = Fixture::new(false);
    assert!(matches!(
        f.with(|mut bytes| {
            bytes.manifest_sha256 = [0; 32];
            AccountArtifacts::authenticate(bytes)
        }),
        Err(Error::PolicyMismatch)
    ));
    let invalid = b"not JSON";
    assert!(matches!(
        f.with(|mut bytes| {
            bytes.manifest = invalid;
            bytes.manifest_sha256 = Sha256::digest(invalid).into();
            AccountArtifacts::authenticate(bytes)
        }),
        Err(Error::InvalidInput)
    ));
    for variant in 0..4 {
        let mut f = Fixture::new(false);
        match variant {
            0 => f.circuit[0] ^= 1,
            1 => f.keys[0] ^= 1,
            2 => f.g1[0] ^= 1,
            _ => f.g2[0] ^= 1,
        }
        assert!(
            matches!(
                f.with(AccountArtifacts::authenticate),
                Err(Error::PolicyMismatch)
            ),
            "variant {variant}"
        );
    }
    for value in ["bad", &"0".repeat(62)] {
        let mut f = Fixture::new(false);
        f.manifest["circuitSha256"] = json!(value);
        assert!(matches!(
            f.with(AccountArtifacts::authenticate),
            Err(Error::InvalidInput)
        ));
    }
}

#[test]
fn artifact_suite_and_setup_shape_are_explicit_and_closed() {
    for variant in 0..16 {
        let mut f = Fixture::new(false);
        match variant {
            0 => f.manifest["version"] = json!(2),
            1 => f.manifest["compiler"] = json!("unsupported"),
            2 => f.manifest["backend"] = json!("unsupported"),
            3 => f.manifest["verifierTarget"] = json!("evm"),
            4 => f.manifest["accountingMode"] = json!("account-extension-v1"),
            5 => f.manifest["hashScheme"] = json!(null),
            6 => f.manifest["numPoints"] = json!(0),
            7 => f.manifest["numPoints"] = json!(64 * 1024 * 1024 / 32 + 1),
            8 => f.manifest["numPoints"] = json!(9 * 131072 + 1),
            9 => f.manifest["setup"] = json!([]),
            10 => f.manifest["setup"][0]["name"] = json!("unknown"),
            11 => f.manifest["setup"][1] = f.manifest["setup"][0].clone(),
            12 => f.manifest["setup"][0]["bytes"] = json!(0),
            13 => f.manifest["setup"][0]["bytes"] = json!(4 * 1024 * 1024 + 1),
            14 => f.manifest["numPoints"] = json!(131073),
            _ => {
                f.g1.truncate(32);
                f.manifest["numPoints"] = json!(1);
                f.manifest["setup"][0]["bytes"] = json!(32);
                f.manifest["setup"][0]["sha256"] = json!(hash(&f.g1));
            }
        }
        assert!(
            matches!(
                f.with(AccountArtifacts::authenticate),
                Err(Error::InvalidInput)
            ),
            "variant {variant}"
        );
    }
}

#[test]
fn bounds_are_checked_before_hashing_or_decoding_large_inputs() {
    let f = Fixture::new(false);
    for variant in 0..5 {
        let size = match variant {
            0 => 65537,
            1 => 64 * 1024 * 1024 + 1,
            2 => 1024 * 1024 + 1,
            3 => 64 * 1024 * 1024 + 1,
            _ => 129,
        };
        let data = vec![0; size];
        assert!(
            matches!(
                f.with(|bytes| {
                    AccountArtifacts::authenticate(ArtifactBytes {
                        manifest: if variant == 0 { &data } else { bytes.manifest },
                        circuit: if variant == 1 { &data } else { bytes.circuit },
                        keys: if variant == 2 { &data } else { bytes.keys },
                        srs_g1: if variant == 3 { &data } else { bytes.srs_g1 },
                        srs_g2: if variant == 4 { &data } else { bytes.srs_g2 },
                        manifest_sha256: bytes.manifest_sha256,
                    })
                }),
                Err(Error::Capacity)
            ),
            "variant {variant}"
        );
    }
    let data = vec![0; 64 * 1024 * 1024];
    assert!(matches!(
        f.with(|bytes| {
            AccountArtifacts::authenticate(ArtifactBytes {
                circuit: &data,
                srs_g1: &data,
                ..bytes
            })
        }),
        Err(Error::Capacity)
    ));
}

#[test]
fn missing_or_malformed_pinned_keys_are_not_native_verifiers() {
    for variant in 0..5 {
        let mut f = Fixture::new(true);
        match variant {
            0 => {
                f.manifest.as_object_mut().unwrap().remove("issuerKey");
            }
            1 => f.manifest["issuerKey"] = json!(vec![1; 63]),
            2 => f.keys = b"invalid JSON".to_vec(),
            3 => f.keys = br#"{"update":"","deposit":"03","record":"05"}"#.to_vec(),
            _ => f.keys = br#"{"update":"invalid","deposit":"03","record":"05"}"#.to_vec(),
        }
        f.manifest["vkSha256"] = json!(hash(&f.keys));
        assert!(
            matches!(f.extension(), Err(Error::InvalidInput)),
            "variant {variant}"
        );
    }
    let mut f = Fixture::new(false);
    f.keys.clear();
    f.manifest["vkSha256"] = json!(hash(&f.keys));
    assert!(matches!(
        f.with(AccountArtifacts::authenticate),
        Err(Error::InvalidInput)
    ));
}

#[test]
fn optional_original_r2_key_is_authenticated_distinct_and_never_substituted() {
    let mut fixture = Fixture::new(true);
    let legacy = fixture.extension().unwrap();
    assert!(legacy.record_epoch_config(options()).is_none());
    fixture.keys =
        br#"{"update":"0102","deposit":"0304","record":"0506","record_epoch":"0708"}"#.to_vec();
    // Adding a capability cannot evade the existing independent manifest pin.
    assert!(matches!(fixture.extension(), Err(Error::PolicyMismatch)));
    fixture.manifest["vkSha256"] = json!(hash(&fixture.keys));
    let artifacts = fixture.extension().unwrap();
    let config = artifacts.record_epoch_config(options()).unwrap();
    assert_eq!(config.verification_key, [7, 8]);
    assert_eq!(config.max_public_inputs, 335);
    assert_eq!(
        config.scope.circuit_digest,
        artifacts.scope().circuit_digest
    );
    assert_eq!(
        config.scope.verifying_key_digest,
        <[u8; 32]>::from(Sha256::digest([7, 8]))
    );
    assert_ne!(
        artifacts.scope().verifying_key_digest,
        legacy.scope().verifying_key_digest
    );
    assert_eq!(config.srs_g1, vec![7; 4 * 1024 * 1024]);
    assert_eq!(config.srs_g2, [8; 128]);
    // The native input is immutable even when host-owned download bytes change.
    fixture.keys.clear();
    assert_eq!(
        artifacts
            .record_epoch_config(options())
            .unwrap()
            .verification_key,
        [7, 8]
    );
    for malformed in ["", "xyz", "0", "AB"] {
        let mut fixture = Fixture::new(true);
        fixture.keys = serde_json::to_vec(
            &json!({"update":"01", "deposit":"02", "record":"03", "record_epoch":malformed}),
        )
        .unwrap();
        fixture.manifest["vkSha256"] = json!(hash(&fixture.keys));
        assert!(
            matches!(fixture.extension(), Err(Error::InvalidInput)),
            "{malformed}"
        );
    }
}

#[test]
fn legacy_group_cannot_route_r2_to_a_legacy_key_or_native_worker() {
    use crate::extensions::{ExtensionPolicy, ExtensionStatement, ExtensionVerifier};
    let artifacts = Fixture::new(true).extension().unwrap();
    let verifier =
        crate::verification::NativeExtensionVerifier::new(options(), options(), artifacts).unwrap();
    let statement = ExtensionStatement::RecordEpoch {
        policy: ExtensionPolicy {
            revision: 1,
            public_record_quorum: 1,
            change_token_cost: 1,
            deposit_delay_seconds: 1,
            minimum_deposit_batch: 2,
            standing_policy_digest: [9; 32],
        },
        record: czkp::record::Record {
            epoch: czkp::record::Epoch {
                purpose: czkp::record::Purpose::RecordEpochV3,
                community: [1; 32],
                policy_epoch: 1,
                epoch: 1,
                starts_at: 1,
                expires_at: 2,
                root: [2; 32],
                issuer_key: [3; 32],
                proof_scope: verifier.scope(),
                leaf_count: 1,
                download_digest: [4; 32],
                download_bytes: 1,
            },
            owner: [5; 32],
            presentation_key: [6; 32],
            blinded_leaf: [7; 32],
            certificate: vec![8; 64],
            shares: None,
        },
    };
    // Deliberately unverified input: lack of capability refuses before parsing,
    // and the missing worker cannot turn this into a generic provider error.
    assert_eq!(
        verifier.verify_anonymous(&statement, b"invalid"),
        Err(Error::UnsupportedCapability)
    );
    assert_eq!(
        verifier.verify(&statement, b"invalid"),
        Err(Error::InvalidInput)
    );
}

#[test]
fn wave_group_authenticates_its_two_keys_and_pins_the_public_widths() {
    // Metadata authentication only; these synthetic keys are never a proof.
    let mut fixture = Fixture::new(true);
    fixture.keys = br#"{"wave":"0102","outcome":"0304"}"#.to_vec();
    fixture.manifest["vkSha256"] = json!(hash(&fixture.keys));
    let group = fixture.with(WaveArtifacts::authenticate).unwrap();
    assert_eq!(group.issuer_key(), [9; 64]);
    let wave = group.wave_config(options());
    let outcome = group.outcome_config(options());
    assert_eq!(wave.max_public_inputs, 586);
    assert_eq!(outcome.max_public_inputs, 619);
    assert_eq!(wave.verification_key, vec![1, 2]);
    assert_eq!(outcome.verification_key, vec![3, 4]);
    assert_ne!(
        wave.scope.verifying_key_digest,
        outcome.scope.verifying_key_digest
    );
    // The account group's key shape is not accepted as a wave group.
    let account = Fixture::new(true);
    assert!(account.with(WaveArtifacts::authenticate).is_err());
    // A missing or empty relation key refuses.
    for keys in [
        br#"{"wave":"0102"}"#.to_vec(),
        br#"{"wave":"","outcome":"0304"}"#.to_vec(),
        br#"{"wave":"0102","outcome":"0304","update":"05"}"#.to_vec(),
    ] {
        let mut broken = Fixture::new(true);
        broken.keys = keys;
        broken.manifest["vkSha256"] = json!(hash(&broken.keys));
        assert!(broken.with(WaveArtifacts::authenticate).is_err());
    }
}
