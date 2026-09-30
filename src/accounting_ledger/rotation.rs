//! Root changes preserve the lifetime pseudonym account and all settlement state.
use super::*;

/// A dual-signed, single-use authority update; never a new account genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootRotation {
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub expected_revision: u64,
    pub expected_version: u64,
    pub expected_state: [u8; 32],
    pub old_root: String,
    pub new_root: String,
    pub old_signature: String,
    pub new_signature: String,
}

/// Canonical bytes signed by both old and new roots.
pub fn root_rotation_bytes(rotation: &RootRotation) -> Result<Vec<u8>, Error> {
    for encoded in [&rotation.old_root, &rotation.new_root] {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&decode::<32>(encoded)?)
            .map_err(|_| Error::Admission)?;
        if key.is_weak() {
            return Err(Error::Admission);
        }
    }
    if rotation.old_root == rotation.new_root || rotation.expected_revision >= MAX_INTEGER {
        return Err(Error::InvalidInput);
    }
    serde_json::to_vec(&(
        "cblc.root-continuity.v1",
        rotation.community,
        rotation.owner,
        rotation.expected_revision,
        rotation.expected_version,
        rotation.expected_state,
        &rotation.old_root,
        &rotation.new_root,
    ))
    .map_err(|_| Error::InvalidInput)
}

pub(super) fn check_root(
    tx: &mut Transaction<'_>,
    owner: &[u8; 32],
    root: &[u8; 32],
) -> Result<(), Error> {
    if tx
        .get::<Frontier>(&key(1, &[owner]))?
        .is_some_and(|prior| prior.root_key != *root)
    {
        return Err(Error::Admission);
    }
    Ok(())
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Rotate authority with proof of continuity and compare-and-swap protection.
    /// Account version, private commitment, inbox and lifetime markers are preserved.
    pub fn rotate_root(&mut self, rotation: &RootRotation) -> Result<(), Error> {
        if rotation.community != self.community {
            return Err(Error::Admission);
        }
        let bytes = root_rotation_bytes(rotation)?;
        signature(&rotation.old_root, &bytes, &rotation.old_signature)?;
        signature(&rotation.new_root, &bytes, &rotation.new_signature)?;
        let mut tx = self.connection.transaction()?;
        check_config(&mut tx, &self.config)?;
        let record_key = key(1, &[&rotation.owner]);
        let mut prior: Frontier = tx.get(&record_key)?.ok_or(Error::Admission)?;
        if prior.root_key != decode::<32>(&rotation.old_root)?
            || prior.root_revision != rotation.expected_revision
            || prior.version != rotation.expected_version
            || prior.state != rotation.expected_state
        {
            return Err(Error::Replay);
        }
        prior.root_key = decode::<32>(&rotation.new_root)?;
        prior.root_revision += 1;
        tx.put(&record_key, &prior)?;
        tx.commit()
    }
}
