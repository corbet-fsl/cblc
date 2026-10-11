//! Original complete snapshot and lineage/publication writes, shared by the
//! legacy owner and the atomic daily settlement transaction.
use super::*;

pub(in crate::accounting_ledger) fn existing_in(
    tx: &mut Transaction<'_>,
    inputs: &prepare::Inputs<'_>,
) -> Result<Option<RecordEpochPublication>, Error> {
    let Some(prior) = tx.get::<RecordEpochPublication>(PUBLISHED)? else {
        if tx.get::<PublishedAnchor>(ANCHOR)?.is_some() {
            return Err(Error::Storage);
        }
        return Ok(None);
    };
    if prior.descriptor.epoch > inputs.epoch {
        return Err(Error::Replay);
    }
    if prior.descriptor.epoch != inputs.epoch {
        return Ok(None);
    }
    prior
        .descriptor
        .validate(&inputs.community, inputs.period_seconds)?;
    let anchor: PublishedAnchor = tx.get(ANCHOR)?.ok_or(Error::Storage)?;
    tuning::check_epoch_config_in(tx, &anchor.configuration, inputs.configuration)?;
    if prior.descriptor.policy_epoch != inputs.policy_epoch
        || &prior.descriptor.proof_scope != inputs.proof_scope
        || anchor.descriptor != prior.descriptor
        || anchor.extension_configuration != inputs.extension_configuration
    {
        return Err(Error::PolicyMismatch);
    }
    let digest: [u8; 32] = Sha256::digest(&prior.object).into();
    if prior.descriptor.download_digest != digest
        || prior.descriptor.download_bytes != prior.object.len() as u64
    {
        return Err(Error::Storage);
    }
    Ok(Some(prior))
}

pub(in crate::accounting_ledger) fn install_in(
    tx: &mut Transaction<'_>,
    frozen: &FrozenEpoch,
    published: &RecordEpochPublication,
    now: u64,
) -> Result<(), Error> {
    // Validate the complete snapshot after encryption. No owner addition,
    // accepted state change, recipient change or late deposit may be missed.
    let rows: Vec<(Vec<u8>, Frontier)> = tx.current_range(&[1], &[2], MAX_FRONTIERS + 1)?;
    if rows.len() != frozen.0.frontiers.len() {
        return Err(Error::Replay);
    }
    let mut leaves = frozen
        .0
        .frontiers
        .iter()
        .map(|frontier| {
            frontier
                .leaf
                .commitment(&frozen.0.community, frozen.0.epoch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    leaves.resize(leaves.len().max(2).next_power_of_two(), [0; 32]);
    let tree = rs_merkle::MerkleTree::<czkp::record::EpochTree>::from_leaves(&leaves);
    if tree.root() != Some(published.descriptor.root) {
        return Err(Error::Storage);
    }
    for (index, ((stored_key, mut current), snapshot)) in
        rows.into_iter().zip(&frozen.0.frontiers).enumerate()
    {
        let leaf = &snapshot.leaf;
        if stored_key != key(1, &[&leaf.owner])
            || current.state != leaf.state
            || current.version != leaf.version
            || crate::extensions::inbox(tx, &leaf.owner)?.root != leaf.required_inbox
            || tx.get::<[u8; 32]>(&recipient_key(&leaf.owner))? != Some(snapshot.recipient_key)
        {
            return Err(Error::Replay);
        }
        current.record_ancestry = Some(Lineage {
            epoch: frozen.0.epoch,
            leaf: czkp::record::Leaf {
                owner: leaf.owner,
                version: leaf.version,
                state: leaf.state,
                required_inbox: leaf.required_inbox,
                blinding: leaf.blinding,
            },
            index: index as u32,
            path: tree.proof(&[index]).proof_hashes().to_vec(),
            consumed: crate::extensions::applied(tx, &leaf.owner)?.root == leaf.required_inbox,
            requires_descendant: crate::extensions::applied(tx, &leaf.owner)?.root
                != leaf.required_inbox,
        });
        tx.put(&stored_key, &current)?;
    }
    tx.put(FROZEN, &frozen.0)?;
    tx.put(PUBLISHED, published)?;
    tx.put(
        ANCHOR,
        &PublishedAnchor {
            descriptor: published.descriptor.clone(),
            period_seconds: frozen.0.period_seconds,
            frozen_at: now,
            configuration: frozen.0.configuration.clone(),
            extension_configuration: frozen.0.extension_configuration.clone(),
        },
    )?;
    Ok(())
}
