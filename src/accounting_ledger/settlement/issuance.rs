//! Original authenticated quota and exact blind-response reconciliation.
use super::*;
use crate::settlement::{SettlementPassRequest, settlement_pass_request_bytes};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    fingerprint: [u8; 32],
    signature: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    context: [u8; 32],
    owner: [u8; 32],
    receipts: BTreeMap<String, Receipt>,
}

fn budgets(
    tx: &mut Transaction<'_>,
    settlement: &Settlement,
    anchor: &IssuerAnchor,
) -> Result<usize, Error> {
    let prefix = scoped_key(BUDGET_PREFIX, &[&settlement.context]);
    let rows: Vec<(Vec<u8>, Budget)> = tx.current_range(
        &prefix,
        &prefix_end(&prefix)?,
        settlement.config.issuance_members_capacity + 1,
    )?;
    let members = rows.len();
    if members > settlement.config.issuance_members_capacity as usize {
        return Err(Error::Capacity);
    }
    let mut issued = 0u64;
    for (stored_key, budget) in rows {
        if budget.context != settlement.context
            || budget.owner == [0; 32]
            || stored_key != scoped_key(&prefix, &[&budget.owner])
            || budget.receipts.is_empty()
            || budget.receipts.len() > usize::from(anchor.quota)
        {
            return Err(Error::Storage);
        }
        for (operation, receipt) in &budget.receipts {
            let operation: [u8; 16] = BASE64URL_NOPAD
                .decode(operation.as_bytes())
                .map_err(|_| Error::Storage)?
                .try_into()
                .map_err(|_| Error::Storage)?;
            if operation == [0; 16]
                || receipt.fingerprint == [0; 32]
                || receipt.signature.len() != cmbl::passes::RSA_BYTES
            {
                return Err(Error::Storage);
            }
        }
        issued = issued
            .checked_add(budget.receipts.len() as u64)
            .ok_or(Error::Storage)?;
    }
    if issued != anchor.issued {
        return Err(Error::Storage);
    }
    Ok(members)
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Issue only under the caller's retained current Policy/member/device
    /// leases, as for ordinary account forwarding. The same configured Policy
    /// supplies the quota and epoch; the request supplies only blinded bytes.
    pub fn issue_settlement_pass(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &SettlementPassRequest,
        clock: impl Fn() -> u64,
    ) -> Result<Vec<u8>, Error> {
        let settlement = self
            .settlement
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let bytes = settlement_pass_request_bytes(request)?;
        if request.community != self.community
            || decode::<32>(&grant.member_id)? != request.owner
            || request.blind.context != settlement.context
            || grant.policy_epoch != settlement.config.policy_epoch
            || request.expires_at - request.issued_at > self.policy.max_authorization_seconds
        {
            return Err(Error::Admission);
        }
        signature(&grant.chat_public_key, &bytes, &request.signature)?;
        let clock = observed_clock(self.observed_time.clone(), clock);
        let before = clock();
        check_time(before, 0)?;
        verify_admission(grant, &self.trust, before)?;
        verify_device_authorization(authorization, grant, before)?;
        let fingerprint: [u8; 32] =
            Sha256::digest(serde_json::to_vec(&request.blind).map_err(|_| Error::InvalidInput)?)
                .into();
        let mut tx = self.connection.transaction()?;
        let now = clock();
        check_time(now, before.max(clock_floor(&mut tx)?))?;
        verify_admission(grant, &self.trust, now)?;
        verify_device_authorization(authorization, grant, now)?;
        if now < request.issued_at
            || now >= request.expires_at
            || now / settlement.config.period_seconds != settlement.config.epoch.epoch
        {
            return Err(Error::Expired);
        }
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, Some(extensions))?;
        check_root(
            &mut tx,
            &request.owner,
            &decode::<32>(&authorization.root_public_key)?,
        )?;
        tx.get::<Frontier>(&key(1, &[&request.owner]))?
            .ok_or(Error::Admission)?;
        let mut anchor = anchor(&mut tx, settlement)?;
        let members = budgets(&mut tx, settlement, &anchor)?;
        let budget_key = scoped_key(BUDGET_PREFIX, &[&settlement.context, &request.owner]);
        let existing: Option<Budget> = tx.get(&budget_key)?;
        if existing.is_none() && members >= settlement.config.issuance_members_capacity as usize {
            return Err(Error::Capacity);
        }
        let mut budget = existing.unwrap_or_else(|| Budget {
            context: settlement.context,
            owner: request.owner,
            receipts: BTreeMap::new(),
        });
        let operation = BASE64URL_NOPAD.encode(&request.operation);
        let prior = budget.receipts.get(&operation);
        if prior.is_some_and(|receipt| receipt.fingerprint != fingerprint) {
            return Err(Error::Replay);
        }
        if prior.is_none() && budget.receipts.len() >= usize::from(settlement.config.quota) {
            return Err(Error::Capacity);
        }
        // The raw operation is deterministic for the original blinded request.
        // Its maintained public fault check also detects a corrupt cached reply.
        let signature = settlement
            .issuer
            .sign(&request.blind, milliseconds(now)?)
            .map_err(crypto_error)?;
        if let Some(prior) = prior {
            if prior.signature != signature {
                return Err(Error::Storage);
            }
        } else {
            budget.receipts.insert(
                operation,
                Receipt {
                    fingerprint,
                    signature: signature.clone(),
                },
            );
            anchor.issued = anchor
                .issued
                .checked_add(1)
                .filter(|n| *n <= MAX_INTEGER)
                .ok_or(Error::Capacity)?;
            tx.put(&budget_key, &budget)?;
            tx.put(&epoch_key(settlement.config.epoch.epoch), &anchor)?;
        }
        let deadline = request
            .expires_at
            .min(grant.expires_at)
            .min(authorization.expires_at)
            .min(settlement.config.expires_at());
        tx.commit_before(&CommitDeadline::new(&clock, now, deadline))?;
        let returned = clock();
        if check_time(returned, now).is_err() || returned >= deadline {
            return Err(Error::Storage);
        }
        Ok(signature)
    }
}
