//! Read-only clock provenance and a quarantined native startup catchup.
use super::*;

pub(in crate::accounting_ledger) fn check_empty(tx: &mut Transaction<'_>) -> Result<(), Error> {
    if !tx
        .current_range::<serde_json::Value>(b"", &[0xff], 1)?
        .is_empty()
    {
        return Err(Error::Storage);
    }
    Ok(())
}

/// Original owner-data observation for the SAME host clock before construction.
/// A missing floor is zero only after a complete bounded range proves all
/// original owner-key namespaces empty. Arbitrary caller byte keys are outside
/// that namespace. This returns no admission or proof/currentness authority.
pub fn startup_clock_floor(store: &mut impl AccountStorage) -> Result<u64, Error> {
    let mut tx = store.transaction()?;
    let config: Option<Vec<u8>> = tx.get(b"config")?;
    let floor = if let Some(config) = config {
        let config: StoredConfig = serde_json::from_slice(&config).map_err(|_| Error::Storage)?;
        config.validate_clock_provenance()?;
        let floor = clock_floor(&mut tx)?;
        if floor > MAX_INTEGER {
            return Err(Error::ClockRollback);
        }
        floor
    } else {
        check_empty(&mut tx)?;
        0
    };
    tx.rollback()?;
    Ok(floor)
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Reopen the one durable owner after Policy may have committed ahead of it.
    /// All immutable config pins are still checked. No handle escapes until ALL
    /// missing transitions verify live and atomically reach the actual Policy
    /// target. New-ledger bootstrap is distinct; malformed state never resets.
    pub fn with_store_reconciled_admission_keys(
        mut store: impl AccountStorage + 'static,
        trust: AdmissionTrust,
        policy: AccountLedgerPolicy,
        verifier: V,
        operator: SigningKey,
        request: AdmissionKeyReconciliation,
        clock: impl Fn() -> u64,
    ) -> Result<Self, Error> {
        request.check_shape()?;
        if trust.policy_keys != request.target.policy_keys {
            return Err(Error::PolicyMismatch);
        }
        let mut tx = store.transaction()?;
        let config: Option<Vec<u8>> = tx.get(b"config")?;
        let installed = if let Some(config) = config {
            let config: StoredConfig =
                serde_json::from_slice(&config).map_err(|_| Error::Storage)?;
            let (_, _, states) = read(&mut tx)?;
            let installed = states.last().ok_or(Error::Storage)?.clone();
            if installed.policy_keys.to_cbor() != config.policy_keys {
                return Err(Error::PolicyMismatch);
            }
            installed
        } else {
            check_empty(&mut tx)?;
            request.target.clone()
        };
        tx.rollback()?;
        let mut previous = trust;
        previous.policy_keys = installed.policy_keys.clone();
        let mut ledger =
            Self::with_store_inner(store, previous, policy, verifier, operator, Some(installed))?;
        ledger.reconcile_admission_keys(request, clock)?;
        Ok(ledger)
    }
}
