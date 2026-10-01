//! Actual public manifest bytes and malformed local-file/configuration cases.
use super::*;
use serde_json::{Value, json};
use std::fs;

const MANIFEST: &[u8] = include_bytes!("../fixtures/extension-manifest.json");
fn scope() -> AccountProofScope {
    let manifest: Value = serde_json::from_slice(MANIFEST).unwrap();
    AccountProofScope {
        circuit_digest: digest(manifest["circuitSha256"].as_str().unwrap()).unwrap(),
        verifying_key_digest: digest(manifest["vkSha256"].as_str().unwrap()).unwrap(),
    }
}
fn install(directory: &Path, manifest: &[u8]) -> std::path::PathBuf {
    fs::write(directory.join("manifest.json"), manifest).unwrap();
    let path = directory.join("config.json");
    fs::write(
        &path,
        serde_json::to_vec(&json!({
            "directory": directory,
            "manifestSha256": HEXLOWER.encode(&Sha256::digest(manifest)),
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

#[test]
fn exact_retained_manifest_binds_scope_hash_and_actual_certificate_key() {
    let directory = tempfile::tempdir().unwrap();
    let path = install(directory.path(), MANIFEST);
    let binding = configured(&path, &scope()).unwrap();
    assert_eq!(
        binding.manifest_sha256,
        <[u8; 32]>::from(Sha256::digest(MANIFEST))
    );
    assert_eq!(
        binding.certificate_key,
        cssr::certificate::CertificateIssuer::new(&[3; 32])
            .unwrap()
            .public_key()
    );
}

#[test]
fn local_file_and_hash_failures_never_supply_a_binding() {
    for variant in 0..14 {
        let directory = tempfile::tempdir().unwrap();
        let mut path = install(directory.path(), MANIFEST);
        let manifest_path = directory.path().join("manifest.json");
        let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut manifest: Value = serde_json::from_slice(MANIFEST).unwrap();
        match variant {
            0 => {
                fs::remove_file(&path).unwrap();
            }
            1 => path = directory.path().into(),
            2 => fs::write(&path, vec![0; 65537]).unwrap(),
            3 => fs::write(&path, b"invalid").unwrap(),
            4 => {
                config["directory"] = "relative".into();
                fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            }
            5 => {
                fs::remove_file(&manifest_path).unwrap();
            }
            6 => {
                fs::write(&manifest_path, vec![0; 65537]).unwrap();
            }
            7 => {
                config["manifestSha256"] = "zz".repeat(32).into();
                fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            }
            8 => {
                config["manifestSha256"] = "00".repeat(31).into();
                fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            }
            9 => {
                config["manifestSha256"] = "00".repeat(32).into();
                fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            }
            10 => {
                path = install(directory.path(), b"invalid manifest");
            }
            11 => {
                manifest["circuitSha256"] = "00".repeat(32).into();
                path = install(directory.path(), &serde_json::to_vec(&manifest).unwrap());
            }
            12 => {
                manifest["vkSha256"] = "00".repeat(32).into();
                path = install(directory.path(), &serde_json::to_vec(&manifest).unwrap());
            }
            _ => {
                manifest["vkSha256"] = "zz".repeat(32).into();
                path = install(directory.path(), &serde_json::to_vec(&manifest).unwrap());
            }
        }
        let expected = match variant {
            0 | 1 | 5 => Error::Storage,
            9 | 11 | 12 => Error::PolicyMismatch,
            _ => Error::InvalidInput,
        };
        assert_eq!(configured(&path, &scope()), Err(expected), "case {variant}");
    }
}
