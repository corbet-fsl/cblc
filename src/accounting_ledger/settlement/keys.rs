//! Minimal historical public-key binding, not a token or member journal.
use super::*;

const PREFIX: &[u8] = b"settlement-key:v1:";
// The original CSSR current_range port permits a depth-20 snapshot plus one
// sentinel. This is an operational bound, not a quota or economic policy.
const MAX_KEYS: u32 = 1 << 20;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyUse {
    format: String,
    epoch: u64,
    context: [u8; 32],
}

fn expected(descriptor: &cmbl::settlement::Epoch) -> Result<(Vec<u8>, KeyUse), Error> {
    // The original maintained context parser validates canonical 3072-bit DER.
    // Installation additionally owns the actual matching private Issuer; no
    // caller hash can substitute for that authenticated public representation.
    let context = descriptor.context().map_err(crypto_error)?;
    let digest: [u8; 32] = Sha256::digest(&descriptor.public_key_der).into();
    Ok((
        scoped_key(PREFIX, &[&digest]),
        KeyUse {
            format: "cblc.settlement.key.v1".into(),
            epoch: descriptor.epoch,
            context,
        },
    ))
}

fn same(stored: &KeyUse, expected: &KeyUse) -> Result<(), Error> {
    if stored.format != expected.format
        || stored.epoch == 0
        || stored.epoch > MAX_INTEGER
        || stored.context == [0; 32]
    {
        return Err(Error::Storage);
    }
    if stored.epoch != expected.epoch || stored.context != expected.context {
        return Err(Error::PolicyMismatch);
    }
    Ok(())
}

pub(super) fn check(
    tx: &mut Transaction<'_>,
    descriptor: &cmbl::settlement::Epoch,
) -> Result<(), Error> {
    let (key, expected) = expected(descriptor)?;
    let stored: KeyUse = tx.get(&key)?.ok_or(Error::Storage)?;
    same(&stored, &expected)
}

pub(super) fn install(
    tx: &mut Transaction<'_>,
    descriptor: &cmbl::settlement::Epoch,
    count: u32,
) -> Result<u32, Error> {
    let (key, expected) = expected(descriptor)?;
    if let Some(stored) = tx.get::<KeyUse>(&key)? {
        same(&stored, &expected)?;
        Ok(count)
    } else {
        let next = count
            .checked_add(1)
            .filter(|n| *n <= MAX_KEYS)
            .ok_or(Error::Capacity)?;
        tx.put(&key, &expected)?;
        Ok(next)
    }
}

pub(super) fn history(
    tx: &mut Transaction<'_>,
    count: u32,
    current_epoch: u64,
    settlement: &Settlement,
) -> Result<(), Error> {
    if count == 0 || count > MAX_KEYS {
        return Err(Error::Storage);
    }
    let anchors: Vec<(Vec<u8>, IssuerAnchor)> =
        tx.current_range(ANCHOR_PREFIX, &prefix_end(ANCHOR_PREFIX)?, count + 1)?;
    let rows: Vec<(Vec<u8>, KeyUse)> = tx.current_range(PREFIX, &prefix_end(PREFIX)?, count + 1)?;
    if anchors.len() != count as usize || rows.len() != count as usize {
        return Err(Error::Storage);
    }
    let mut indexed = std::collections::BTreeMap::new();
    for (key, row) in rows {
        if indexed.insert(key, row).is_some() {
            return Err(Error::Storage);
        }
    }
    for (key, anchor) in anchors {
        if anchor.format != "cblc.settlement.issuer.v1"
            || key != epoch_key(anchor.descriptor.epoch)
            || anchor.descriptor.epoch > current_epoch
            || anchor.descriptor.community != settlement.config.epoch.community
            || anchor.policy_epoch == 0
            || anchor.policy_epoch > MAX_INTEGER
            || anchor.issued > MAX_INTEGER
            || !(1..=1024).contains(&anchor.quota)
            || anchor.incarnation.is_empty()
            || anchor.incarnation.len() > 256
        {
            return Err(Error::Storage);
        }
        crate::settlement::SettlementCapability {
            epoch: anchor.descriptor.clone(),
            policy_epoch: anchor.policy_epoch,
            period_seconds: settlement.config.period_seconds,
            quota: anchor.quota,
        }
        .validate(&settlement.config.epoch.community, anchor.policy_epoch)
        .map_err(|_| Error::Storage)?;
        if anchor.policy_epoch > settlement.config.policy_epoch {
            return Err(Error::ClockRollback);
        }
        let (key, binding) = expected(&anchor.descriptor)?;
        let row = indexed.remove(&key).ok_or(Error::Storage)?;
        same(&row, &binding)?;
    }
    if !indexed.is_empty() {
        return Err(Error::Storage);
    }
    Ok(())
}
