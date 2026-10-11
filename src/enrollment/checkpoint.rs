//! Original depth32 enrollment encoding through maintained CZKP Poseidon2.
use super::{VerifiedDelegation, publication::EnrollmentEntry};
use crate::Error;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

type Field = [u8; 32];
const DEPTH: usize = 32;

/// Computed public enrollment tree. It is not a publisher or admitted-root
/// capability: a common publication must freeze the complete registry snapshot.
pub struct EnrollmentTree {
    root: Field,
    entries: Vec<EnrollmentEntry>,
    leaves: Vec<Field>,
    paths: Vec<[Field; DEPTH]>,
}
impl EnrollmentTree {
    /// Encode sorted unique authenticated headers with the original relation.
    /// The publication service separately owns freshness and whole-slot filtering.
    pub fn from_verified(values: &[VerifiedDelegation]) -> Result<Self, Error> {
        if values.is_empty() || values.len() > 65536 {
            return Err(Error::Admission);
        }
        let first = values[0].delegation();
        let community: Field = Sha256::digest(first.admission.community_id.as_bytes()).into();
        let mut entries = Vec::with_capacity(values.len());
        for value in values {
            let d = value.delegation();
            if d.admission.community_id != first.admission.community_id
                || d.admission.policy_digest != first.admission.policy_digest
                || d.admission.policy_epoch != first.admission.policy_epoch
                || d.admission.passport_policy_digest != first.admission.passport_policy_digest
                || value.checked_at() != values[0].checked_at()
            {
                return Err(Error::Admission);
            }
            entries.push(EnrollmentEntry::from_verified(value));
        }
        Self::from_entries(community, entries)
    }
    // This distinct internal input can only arise after authenticating the
    // original frozen object/context; it never escapes as current admission.
    #[cfg(feature = "host")]
    pub(super) fn from_historical(
        values: &[super::delegation::HistoricalDelegation],
    ) -> Result<Self, Error> {
        let first = values.first().ok_or(Error::Admission)?;
        let community: Field =
            Sha256::digest(first.delegation.admission.community_id.as_bytes()).into();
        let entries = values
            .iter()
            .map(|v| EnrollmentEntry::from_delegation(&v.delegation, v.digest))
            .collect();
        Self::from_entries(community, entries)
    }
    fn from_entries(community: Field, mut entries: Vec<EnrollmentEntry>) -> Result<Self, Error> {
        if entries.is_empty() || entries.len() > 65536 {
            return Err(Error::Admission);
        }
        entries.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        if entries
            .windows(2)
            .any(|pair| pair[0].member_id == pair[1].member_id)
        {
            return Err(Error::Admission);
        }
        let leaves = entries
            .iter()
            .map(|entry| leaf(&community, entry))
            .collect::<Result<Vec<_>, _>>()?;
        let mut empty = [[0; 32]; DEPTH + 1];
        for level in 0..DEPTH {
            empty[level + 1] = node(&empty[level], &empty[level])?;
        }
        let mut levels = Vec::with_capacity(DEPTH + 1);
        levels.push(
            leaves
                .iter()
                .enumerate()
                .map(|(i, value)| (i as u32, *value))
                .collect::<BTreeMap<_, _>>(),
        );
        for level in 0..DEPTH {
            let current = &levels[level];
            let parents = current
                .keys()
                .map(|index| index >> 1)
                .collect::<BTreeSet<_>>();
            let mut next = BTreeMap::new();
            for parent in parents {
                let left = current.get(&(parent * 2)).unwrap_or(&empty[level]);
                let right = current.get(&(parent * 2 + 1)).unwrap_or(&empty[level]);
                next.insert(parent, node(left, right)?);
            }
            levels.push(next);
        }
        let root = *levels[DEPTH].get(&0).ok_or(Error::Admission)?;
        let paths = (0..entries.len())
            .map(|index| {
                let mut path = [[0; 32]; DEPTH];
                for level in 0..DEPTH {
                    let position = (index as u32) >> level;
                    path[level] = *levels[level].get(&(position ^ 1)).unwrap_or(&empty[level]);
                }
                path
            })
            .collect();
        Ok(Self {
            root,
            entries,
            leaves,
            paths,
        })
    }
    /// Exact canonical common-root candidate, without installation authority.
    pub fn root(&self) -> Field {
        self.root
    }
    /// Original sorted public headers in their authenticated leaf positions.
    pub fn entries(&self) -> &[EnrollmentEntry] {
        &self.entries
    }
    /// Native-maintained leaf values, useful to the original private holder.
    pub fn leaves(&self) -> &[Field] {
        &self.leaves
    }
    /// Exact depth32 membership paths for these public headers.
    pub fn paths(&self) -> &[[Field; DEPTH]] {
        &self.paths
    }
}
fn domain(label: &[u8]) -> Field {
    let mut value = [0; 32];
    value[32 - label.len()..].copy_from_slice(label);
    value
}
fn node(left: &Field, right: &Field) -> Result<Field, Error> {
    czkp::poseidon::hash(&[
        domain(b"cfrm.accounting.poseidon2.v1"),
        czkp::poseidon::integer(6),
        *left,
        *right,
    ])
}
fn leaf(community: &Field, entry: &EnrollmentEntry) -> Result<Field, Error> {
    entry.validate()?;
    let member = czkp::decode::<32>(&entry.member_id)?;
    let key = super::publication::hex::<64>(&entry.account_key)?;
    let x: Field = key[..32].try_into().map_err(|_| Error::Admission)?;
    let y: Field = key[32..].try_into().map_err(|_| Error::Admission)?;
    let secret = super::publication::hex::<32>(&entry.secret_hash)?;
    let delegation = super::publication::hex::<32>(&entry.delegation_digest)?;
    if delegation == [0; 32] {
        return Err(Error::Admission);
    }
    let mut fields = vec![domain(b"cfrm.account-state.v2"), czkp::poseidon::integer(1)];
    for bytes in [community, &member, &x, &y] {
        fields.extend(czkp::poseidon::limbs(bytes));
    }
    fields.extend([
        secret,
        czkp::poseidon::integer(entry.issued_at),
        czkp::poseidon::integer(entry.expires_at),
    ]);
    fields.extend(czkp::poseidon::limbs(&delegation));
    czkp::poseidon::hash(&fields)
}
