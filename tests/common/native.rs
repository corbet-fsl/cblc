//! Host-side loading of fictional public proof fixtures. Domain libraries receive
//! authenticated RAM snapshots and never open these files themselves.
#![allow(dead_code)]
use cblc::{
    Error,
    artifacts::{AccountArtifacts, ArtifactBytes, ExtensionArtifacts, NativeVerifierOptions},
};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    directory: PathBuf,
    manifest_sha256: String,
}

fn configuration(path: &Path) -> Config {
    assert!(path.is_absolute());
    let value: Config = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(value.directory.is_absolute());
    value
}

fn manifest_pin(text: &str) -> [u8; 32] {
    data_encoding::HEXLOWER
        .decode(text.as_bytes())
        .unwrap()
        .try_into()
        .unwrap()
}

pub fn options(max_proof_bytes: usize) -> NativeVerifierOptions {
    NativeVerifierOptions {
        executable: std::env::var_os("CBLC_BB")
            .expect("CI must provide the native verifier worker")
            .into(),
        timeout: Duration::from_secs(180),
        maximum_parallel: 1,
        max_proof_bytes,
        threads: 1,
        memory_megabytes: 8192,
    }
}

pub fn account(directory: &Path) -> AccountArtifacts {
    let config = configuration(&directory.join("config.json"));
    let directory = config.directory;
    let manifest = std::fs::read(directory.join("manifest.json")).unwrap();
    let circuit = std::fs::read(directory.join("circuit.json")).unwrap();
    let keys = std::fs::read(directory.join("vk.bin")).unwrap();
    let srs_g1 = std::fs::read(directory.join("setup/g1.dat")).unwrap();
    let srs_g2 = std::fs::read(directory.join("setup/g2.dat")).unwrap();
    AccountArtifacts::authenticate(ArtifactBytes {
        manifest: &manifest,
        manifest_sha256: manifest_pin(&config.manifest_sha256),
        circuit: &circuit,
        keys: &keys,
        srs_g1: &srs_g1,
        srs_g2: &srs_g2,
    })
    .unwrap()
}

pub fn extension_config(path: &Path) -> Result<ExtensionArtifacts, Error> {
    let config = configuration(path);
    extension_pinned(&config.directory, manifest_pin(&config.manifest_sha256))
}

pub fn extension(directory: &Path) -> ExtensionArtifacts {
    extension_config(&directory.join("config.json")).unwrap()
}

pub fn extension_pinned(directory: &Path, pin: [u8; 32]) -> Result<ExtensionArtifacts, Error> {
    let manifest = std::fs::read(directory.join("manifest.json")).unwrap();
    let circuit = std::fs::read(directory.join("circuits.json")).unwrap();
    let keys = std::fs::read(directory.join("keys.json")).unwrap();
    let srs_g1 = std::fs::read(directory.join("setup/g1.dat")).unwrap();
    let srs_g2 = std::fs::read(directory.join("setup/g2.dat")).unwrap();
    ExtensionArtifacts::authenticate(ArtifactBytes {
        manifest: &manifest,
        manifest_sha256: pin,
        circuit: &circuit,
        keys: &keys,
        srs_g1: &srs_g1,
        srs_g2: &srs_g2,
    })
}

pub fn extension_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".extension-test")
}
