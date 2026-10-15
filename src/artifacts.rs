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
    /// Former pin of the certificate issuer key. The issuer key ring lives in the signed
    /// verifier status now, so a manifest that still pins a key is refused.
    issuer_key: Option<Vec<u8>>,
}

/// Noir ABI type, only as far as the public width needs it.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum AbiType {
    Field,
    Integer,
    Boolean,
    String { length: usize },
    Array { length: usize, r#type: Box<AbiType> },
    Struct { fields: Vec<AbiNamed> },
    Tuple { fields: Vec<AbiType> },
}

#[derive(Deserialize)]
struct AbiNamed {
    r#type: AbiType,
}

#[derive(Deserialize)]
struct AbiParameter {
    r#type: AbiType,
    visibility: String,
}

#[derive(Deserialize)]
struct AbiProgram {
    abi: AbiParameters,
}

#[derive(Deserialize)]
struct AbiParameters {
    parameters: Vec<AbiParameter>,
}

impl AbiType {
    /// Public input fields: one per scalar, byte or array element, as in the Noir ABI.
    fn width(&self) -> Result<usize, Error> {
        Ok(match self {
            Self::Field | Self::Integer | Self::Boolean => 1,
            Self::String { length } => *length,
            Self::Array { length, r#type } => length
                .checked_mul(r#type.width()?)
                .ok_or(Error::InvalidInput)?,
            Self::Struct { fields } => fields.iter().try_fold(0usize, |sum, field| {
                sum.checked_add(field.r#type.width()?)
                    .ok_or(Error::InvalidInput)
            })?,
            Self::Tuple { fields } => fields.iter().try_fold(0usize, |sum, field| {
                sum.checked_add(field.width()?).ok_or(Error::InvalidInput)
            })?,
        })
    }
}

/// Number of public input fields of every named relation, read from the authenticated
/// compiled circuits themselves instead of repeated as constants.
fn public_widths(
    circuit: &[u8],
    kinds: &[&str],
) -> Result<std::collections::BTreeMap<String, usize>, Error> {
    let programs: std::collections::BTreeMap<String, AbiProgram> =
        serde_json::from_slice(circuit).map_err(|_| Error::InvalidInput)?;
    let mut widths = std::collections::BTreeMap::new();
    for kind in kinds {
        let program = programs.get(*kind).ok_or(Error::InvalidInput)?;
        let mut width = 0usize;
        for parameter in &program.abi.parameters {
            if parameter.visibility == "public" {
                width = width
                    .checked_add(parameter.r#type.width()?)
                    .ok_or(Error::InvalidInput)?;
            }
        }
        if width == 0 {
            return Err(Error::InvalidInput);
        }
        widths.insert((*kind).to_owned(), width);
    }
    Ok(widths)
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
        || manifest.issuer_key.is_some()
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
    /// The unlinkable voucher presentation, available with the record epoch group.
    voucher_epoch: Option<String>,
}

/// Immutable extension group: circuits and verifying keys only. The certificate issuer
/// keys are published as a ring in the signed verifier status, never pinned here.
#[derive(Clone)]
pub struct ExtensionArtifacts {
    material: Material,
    keys: [Vec<u8>; 3],
    record_epoch_key: Option<Vec<u8>>,
    voucher_epoch_key: Option<Vec<u8>>,
    /// Public input fields read from the authenticated circuits' ABI.
    widths: Widths,
}

#[derive(Clone)]
struct Widths {
    update: usize,
    deposit: usize,
    record: usize,
    record_epoch: usize,
    voucher_epoch: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ArtifactBinding {
    pub manifest_sha256: [u8; 32],
}

impl ExtensionArtifacts {
    pub fn authenticate(bytes: ArtifactBytes<'_>) -> Result<Self, Error> {
        let (material, _) = material(&bytes, true)?;
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
        let optional = |key: Option<String>| {
            key.map(|text| {
                if text.is_empty() {
                    return Err(Error::InvalidInput);
                }
                HEXLOWER
                    .decode(text.as_bytes())
                    .map_err(|_| Error::InvalidInput)
            })
            .transpose()
        };
        let record_epoch_key = optional(keys.record_epoch)?;
        let voucher_epoch_key = optional(keys.voucher_epoch)?;
        let mut kinds = vec!["update", "deposit", "record"];
        if record_epoch_key.is_some() {
            kinds.push("record_epoch");
        }
        if voucher_epoch_key.is_some() {
            kinds.push("voucher_epoch");
        }
        let widths = public_widths(bytes.circuit, &kinds)?;
        let width = |kind: &str| widths.get(kind).copied().unwrap_or(0);
        let widths = Widths {
            update: width("update"),
            deposit: width("deposit"),
            record: width("record"),
            record_epoch: width("record_epoch"),
            voucher_epoch: width("voucher_epoch"),
        };
        Ok(Self {
            material,
            keys: decoded,
            record_epoch_key,
            voucher_epoch_key,
            widths,
        })
    }
    pub fn scope(&self) -> AccountProofScope {
        self.material.scope.clone()
    }
    /// Pin authenticated together with the group scope.
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.material.manifest_sha256
    }
    pub(crate) fn binding(&self) -> ArtifactBinding {
        ArtifactBinding {
            manifest_sha256: self.manifest_sha256(),
        }
    }
    pub(crate) fn configs(
        &self,
        updates: NativeVerifierOptions,
        anonymous: NativeVerifierOptions,
    ) -> [cvfy::NativeVerifierConfig; 3] {
        [
            self.material
                .config(updates, self.keys[0].clone(), self.widths.update),
            self.material
                .config(anonymous.clone(), self.keys[1].clone(), self.widths.deposit),
            self.material
                .config(anonymous, self.keys[2].clone(), self.widths.record),
        ]
    }
    pub(crate) fn record_epoch_config(
        &self,
        options: NativeVerifierOptions,
    ) -> Option<cvfy::NativeVerifierConfig> {
        self.record_epoch_key.as_ref().map(|key| {
            self.material
                .config(options, key.clone(), self.widths.record_epoch)
        })
    }
    pub(crate) fn voucher_epoch_config(
        &self,
        options: NativeVerifierOptions,
    ) -> Option<cvfy::NativeVerifierConfig> {
        self.voucher_epoch_key.as_ref().map(|key| {
            self.material
                .config(options, key.clone(), self.widths.voucher_epoch)
        })
    }
}

/// Public fields of the update relation, as the compiled circuit currently declares them
/// (the verifier itself reads the width from the authenticated ABI; this is the pin that
/// tests compare against so a circuit change is never silent).
pub const UPDATE_WIDTH: usize = 410;
/// Public fields of the unlinkable voucher presentation (no owner, no shares): the record
/// epoch statement, purpose, uses, time, tag, binding, sign-off threshold and 16 nullifiers.
pub const VOUCHER_EPOCH_WIDTH: usize = 381;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaveKeys {
    wave: String,
    outcome: String,
}

/// Immutable peer-release group: the `wave` and `outcome` relations on main's
/// core. It never joins the account group and pins no issuer key.
#[derive(Clone)]
pub struct WaveArtifacts {
    material: Material,
    wave_key: Vec<u8>,
    outcome_key: Vec<u8>,
    wave_width: usize,
    outcome_width: usize,
}

impl WaveArtifacts {
    pub fn authenticate(bytes: ArtifactBytes<'_>) -> Result<Self, Error> {
        let (material, _) = material(&bytes, true)?;
        let keys: WaveKeys = serde_json::from_slice(bytes.keys).map_err(|_| Error::InvalidInput)?;
        let decode = |text: String| {
            if text.is_empty() {
                return Err(Error::InvalidInput);
            }
            HEXLOWER
                .decode(text.as_bytes())
                .map_err(|_| Error::InvalidInput)
        };
        let widths = public_widths(bytes.circuit, &["wave", "outcome"])?;
        Ok(Self {
            material,
            wave_key: decode(keys.wave)?,
            outcome_key: decode(keys.outcome)?,
            wave_width: widths["wave"],
            outcome_width: widths["outcome"],
        })
    }
    pub fn scope(&self) -> AccountProofScope {
        self.material.scope.clone()
    }
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.material.manifest_sha256
    }
    /// Verifier configuration for reservation evidence (public fields from the ABI).
    pub fn wave_config(&self, options: NativeVerifierOptions) -> cvfy::NativeVerifierConfig {
        self.material
            .config(options, self.wave_key.clone(), self.wave_width)
    }
    /// Verifier configuration for settled outcomes (public fields from the ABI).
    pub fn outcome_config(&self, options: NativeVerifierOptions) -> cvfy::NativeVerifierConfig {
        self.material
            .config(options, self.outcome_key.clone(), self.outcome_width)
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
