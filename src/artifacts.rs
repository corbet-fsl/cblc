//! Authenticated public verifier material supplied in RAM by the host.
//! This library opens no artifact files and never discovers network locations.
use crate::{Error, accounting::AccountProofScope};
use data_encoding::HEXLOWER;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};

#[cfg(test)]
mod tests;

/// Host-read public artifacts. The manifest pin is trusted application
/// configuration, obtained independently of the artifact download.
pub struct ArtifactBytes<'a> {
    pub manifest: &'a [u8],
    pub manifest_sha256: [u8; 32],
    /// Account circuit.json or extension circuits.json, hashed before use.
    pub circuit: &'a [u8],
    /// Account vk.bin or extension keys.json.
    pub keys: &'a [u8],
    pub srs_g1: &'a [u8],
    pub srs_g2: &'a [u8],
}

/// Explicit execution limits, independent of economic account policy.
#[derive(Clone)]
pub struct NativeVerifierOptions {
    pub executable: PathBuf,
    pub timeout: Duration,
    pub maximum_parallel: usize,
    pub max_proof_bytes: usize,
    pub threads: usize,
    pub memory_megabytes: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    version: u8,
    compiler: String,
    backend: String,
    verifier_target: String,
    accounting_mode: String,
    hash_scheme: Option<String>,
    circuit_sha256: String,
    vk_sha256: String,
    num_points: usize,
    setup: Vec<Setup>,
    issuer_key: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct Setup {
    name: String,
    bytes: usize,
    sha256: String,
}

#[derive(Clone)]
struct Material {
    scope: AccountProofScope,
    manifest_sha256: [u8; 32],
    g1: Vec<u8>,
    g2: [u8; 128],
}

fn digest(text: &str) -> Result<[u8; 32], Error> {
    HEXLOWER
        .decode(text.as_bytes())
        .map_err(|_| Error::InvalidInput)?
        .try_into()
        .map_err(|_| Error::InvalidInput)
}

fn authenticated(bytes: &[u8], expected: &str) -> Result<(), Error> {
    if <[u8; 32]>::from(Sha256::digest(bytes)) != digest(expected)? {
        return Err(Error::PolicyMismatch);
    }
    Ok(())
}

fn material(bytes: &ArtifactBytes<'_>, extension: bool) -> Result<(Material, Manifest), Error> {
    let maximum = if extension {
        128 * 1024 * 1024
    } else {
        64 * 1024 * 1024
    };
    if bytes.manifest.len() > 65536
        || bytes.circuit.len() > 64 * 1024 * 1024
        || bytes.keys.len() > 1024 * 1024
        || bytes.srs_g1.len() > maximum
        || bytes.srs_g2.len() != 128
        || [
            bytes.manifest.len(),
            bytes.circuit.len(),
            bytes.keys.len(),
            bytes.srs_g1.len(),
            bytes.srs_g2.len(),
        ]
        .into_iter()
        .sum::<usize>()
            > 2 * maximum
    {
        return Err(Error::Capacity);
    }
    if <[u8; 32]>::from(Sha256::digest(bytes.manifest)) != bytes.manifest_sha256 {
        return Err(Error::PolicyMismatch);
    }
    let manifest: Manifest =
        serde_json::from_slice(bytes.manifest).map_err(|_| Error::InvalidInput)?;
    let mode = if extension {
        "account-extension-v1"
    } else {
        "account-state-v2"
    };
    if manifest.version != 1
        || manifest.compiler != "1.0.0-beta.26"
        || manifest.backend != "5.2.1"
        || manifest.verifier_target != "noir-recursive"
        || manifest.accounting_mode != mode
        || (!extension && manifest.hash_scheme.as_deref() != Some("poseidon2-bn254-fixed-128-v1"))
        || manifest.num_points == 0
        || manifest.num_points > maximum / 32
        || (!extension && manifest.num_points > 9 * 131072)
        || manifest.setup.len() != 2
    {
        return Err(Error::InvalidInput);
    }
    authenticated(bytes.circuit, &manifest.circuit_sha256)?;
    authenticated(bytes.keys, &manifest.vk_sha256)?;
    let mut seen = [false; 2];
    for setup in &manifest.setup {
        let (index, data) = match setup.name.as_str() {
            "g1.dat" => (0, bytes.srs_g1),
            "g2.dat" => (1, bytes.srs_g2),
            _ => return Err(Error::InvalidInput),
        };
        if seen[index] || setup.bytes == 0 || setup.bytes != data.len() {
            return Err(Error::InvalidInput);
        }
        seen[index] = true;
        authenticated(data, &setup.sha256)?;
    }
    if bytes.srs_g1.len() != manifest.num_points * 32 || bytes.srs_g1.len() < 4 * 1024 * 1024 {
        return Err(Error::InvalidInput);
    }
    let scope = AccountProofScope {
        circuit_digest: digest(&manifest.circuit_sha256)?,
        verifying_key_digest: digest(&manifest.vk_sha256)?,
    };
    let mut g2 = [0; 128];
    g2.copy_from_slice(bytes.srs_g2);
    Ok((
        Material {
            scope,
            manifest_sha256: bytes.manifest_sha256,
            // The native verifier requires the first authenticated compressed CRS
            // chunk. Authenticate the entire supplied setup before taking its prefix.
            g1: bytes.srs_g1[..4 * 1024 * 1024].to_vec(),
            g2,
        },
        manifest,
    ))
}

/// Immutable account verification material, authenticated before construction.
#[derive(Clone)]
pub struct AccountArtifacts {
    material: Material,
    key: Vec<u8>,
}
impl AccountArtifacts {
    pub fn authenticate(bytes: ArtifactBytes<'_>) -> Result<Self, Error> {
        let (material, _) = material(&bytes, false)?;
        if bytes.keys.is_empty() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            material,
            key: bytes.keys.to_vec(),
        })
    }
    pub fn scope(&self) -> AccountProofScope {
        self.material.scope.clone()
    }
    pub(crate) fn config(&self, options: NativeVerifierOptions) -> cvfy::NativeVerifierConfig {
        self.material.config(options, self.key.clone(), 243)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Keys {
    update: String,
    deposit: String,
    record: String,
    /// Original R2 is a distinct circuit, never the legacy record key.
    record_epoch: Option<String>,
}

/// Immutable extension group, including the pinned certificate issuer key.
#[derive(Clone)]
pub struct ExtensionArtifacts {
    material: Material,
    pub(crate) issuer: [u8; 64],
    keys: [Vec<u8>; 3],
    record_epoch_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ArtifactBinding {
    pub manifest_sha256: [u8; 32],
    pub certificate_key: [u8; 64],
}

impl ExtensionArtifacts {
    pub fn authenticate(bytes: ArtifactBytes<'_>) -> Result<Self, Error> {
        let (material, manifest) = material(&bytes, true)?;
        let issuer = manifest
            .issuer_key
            .ok_or(Error::InvalidInput)?
            .try_into()
            .map_err(|_| Error::InvalidInput)?;
        let keys: Keys = serde_json::from_slice(bytes.keys).map_err(|_| Error::InvalidInput)?;
        let mut decoded = [Vec::new(), Vec::new(), Vec::new()];
        for (target, text) in decoded
            .iter_mut()
            .zip([keys.update, keys.deposit, keys.record])
        {
            if text.is_empty() {
                return Err(Error::InvalidInput);
            }
            *target = HEXLOWER
                .decode(text.as_bytes())
                .map_err(|_| Error::InvalidInput)?;
        }
        let record_epoch_key = keys
            .record_epoch
            .map(|text| {
                if text.is_empty() {
                    return Err(Error::InvalidInput);
                }
                HEXLOWER
                    .decode(text.as_bytes())
                    .map_err(|_| Error::InvalidInput)
            })
            .transpose()?;
        Ok(Self {
            material,
            issuer,
            keys: decoded,
            record_epoch_key,
        })
    }
    pub fn scope(&self) -> AccountProofScope {
        self.material.scope.clone()
    }
    /// Pin authenticated together with the group scope and issuer key.
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.material.manifest_sha256
    }
    pub(crate) fn binding(&self) -> ArtifactBinding {
        ArtifactBinding {
            manifest_sha256: self.manifest_sha256(),
            certificate_key: self.issuer,
        }
    }
    pub(crate) fn configs(
        &self,
        updates: NativeVerifierOptions,
        anonymous: NativeVerifierOptions,
    ) -> [cvfy::NativeVerifierConfig; 3] {
        [
            self.material.config(updates, self.keys[0].clone(), 345),
            self.material
                .config(anonymous.clone(), self.keys[1].clone(), 262),
            self.material.config(anonymous, self.keys[2].clone(), 172),
        ]
    }
    pub(crate) fn record_epoch_config(
        &self,
        options: NativeVerifierOptions,
    ) -> Option<cvfy::NativeVerifierConfig> {
        self.record_epoch_key
            .as_ref()
            .map(|key| self.material.config(options, key.clone(), 303))
    }
}

impl Material {
    fn config(
        &self,
        options: NativeVerifierOptions,
        key: Vec<u8>,
        maximum: usize,
    ) -> cvfy::NativeVerifierConfig {
        cvfy::NativeVerifierConfig {
            executable: options.executable,
            scope: AccountProofScope {
                circuit_digest: self.scope.circuit_digest,
                verifying_key_digest: Sha256::digest(&key).into(),
            },
            timeout: options.timeout,
            maximum_parallel: options.maximum_parallel,
            max_proof_bytes: options.max_proof_bytes,
            max_public_inputs: maximum,
            threads: options.threads,
            memory_megabytes: options.memory_megabytes,
            verification_key: key,
            srs_g1: self.g1.clone(),
            srs_g2: self.g2,
        }
    }
}
