//! Original all-frontier preparation under the caller's one transaction.
use super::*;

pub(in crate::accounting_ledger) struct Inputs<'a> {
    pub community: [u8; 32],
    pub issuer_key: [u8; 32],
    pub policy_epoch: u64,
    pub epoch: u64,
    pub period_seconds: u64,
    pub now: u64,
    pub configuration: &'a [u8],
    pub extension_configuration: &'a [u8],
    pub proof_scope: &'a AccountProofScope,
}

pub(in crate::accounting_ledger) fn prepare_in(
    tx: &mut Transaction<'_>,
    inputs: &Inputs<'_>,
    clock: &dyn Fn() -> u64,
) -> Result<FrozenEpoch, Error> {
    let rows: Vec<(Vec<u8>, Frontier)> = tx.current_range(&[1], &[2], MAX_FRONTIERS + 1)?;
    if rows.is_empty() || rows.len() > MAX_FRONTIERS as usize {
        return Err(Error::Capacity);
    }
    let mut frontiers = Vec::with_capacity(rows.len());
    for (stored_key, frontier) in rows {
        if stored_key.len() != 41 || stored_key[1..9] != 32_u64.to_be_bytes() {
            return Err(Error::Storage);
        }
        let owner: [u8; 32] = stored_key[9..].try_into().map_err(|_| Error::Storage)?;
        let recipient = tx
            .get::<[u8; 32]>(&recipient_key(&owner))?
            .ok_or(Error::Admission)?;
        if recipient == [0; 32] {
            return Err(Error::Storage);
        }
        let mut blinding = [0; 32];
        getrandom::fill(&mut blinding).map_err(|_| Error::CryptoProvider)?;
        let leaf = czkp::record::Leaf {
            owner,
            version: frontier.version,
            state: frontier.state,
            required_inbox: crate::extensions::inbox(tx, &owner)?.root,
            role: super::super::voucher::role_of(tx, &owner)?,
            blinding,
        };
        leaf.commitment(&inputs.community, inputs.epoch)?;
        frontiers.push(FrozenFrontier {
            recipient_key: recipient,
            leaf,
        });
    }
    let completed = clock();
    check_time(completed, inputs.now)?;
    if completed / inputs.period_seconds != inputs.epoch {
        return Err(Error::Expired);
    }
    let frozen = FrozenEpochState {
        community: inputs.community,
        issuer_key: inputs.issuer_key,
        policy_epoch: inputs.policy_epoch,
        epoch: inputs.epoch,
        period_seconds: inputs.period_seconds,
        frozen_at: completed,
        configuration: inputs.configuration.to_vec(),
        extension_configuration: inputs.extension_configuration.to_vec(),
        proof_scope: inputs.proof_scope.clone(),
        frontiers,
    };
    Ok(FrozenEpoch(frozen))
}
