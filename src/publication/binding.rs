//! Read only the already configured public artifact metadata. The real worker
//! authenticates the complete circuit, key and setup files when verifying proofs.
use crate::{Error, accounting::AccountProofScope};
use data_encoding::HEXLOWER;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub manifest_sha256: [u8; 32],
    pub certificate_key: Vec<u8>,
}

#[cfg(test)]
#[path = "../../tests/internal/publication_binding.rs"]
mod tests;

fn bounded(path: &Path) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Error::Storage)?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Storage)?;
    if bytes.len() > 65536 {
        return Err(Error::InvalidInput);
    }
    Ok(bytes)
}

fn digest(value: &str) -> Result<[u8; 32], Error> {
    HEXLOWER
        .decode(value.as_bytes())
        .map_err(|_| Error::InvalidInput)?
        .try_into()
        .map_err(|_| Error::InvalidInput)
}

pub(crate) fn configured(path: &Path, scope: &AccountProofScope) -> Result<Binding, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Config {
        directory: std::path::PathBuf,
        manifest_sha256: String,
    }
    // The signed hash covers every manifest field. Parse only the duplicated
    // bindings that this producer must compare to its actual active authority.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Manifest {
        circuit_sha256: String,
        vk_sha256: String,
        issuer_key: Vec<u8>,
    }
    let config: Config =
        serde_json::from_slice(&bounded(path)?).map_err(|_| Error::InvalidInput)?;
    if !config.directory.is_absolute() {
        return Err(Error::InvalidInput);
    }
    let bytes = bounded(&config.directory.join("manifest.json"))?;
    let manifest_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    if manifest_sha256 != digest(&config.manifest_sha256)? {
        return Err(Error::PolicyMismatch);
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)?;
    if digest(&manifest.circuit_sha256)? != scope.circuit_digest
        || digest(&manifest.vk_sha256)? != scope.verifying_key_digest
    {
        return Err(Error::PolicyMismatch);
    }
    Ok(Binding {
        manifest_sha256,
        certificate_key: manifest.issuer_key,
    })
}
