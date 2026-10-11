//! Private daily settlement owner. Only actual native verification may create
//! durable pending facts; no proof bytes or asserted verifier results persist.
use super::*;
use crate::settlement::{SettlementConfig, crypto_error, milliseconds};
use cmbl::settlement::issuer::Issuer;

mod freeze;
mod ingress;
mod issuance;
mod keys;

enum KeySource<'a> {
    Encoded(&'a [u8]),
    Issuer(Issuer),
}

const MODE: &[u8] = b"settlement-mode:v1";
const ANCHOR_PREFIX: &[u8] = b"settlement-issuer:v1:";
const BUDGET_PREFIX: &[u8] = b"settlement-budget:v1:";
const FACT_PREFIX: &[u8] = b"settlement-pending:v1:";
const TOKEN_PREFIX: &[u8] = b"settlement-token:v1:";
const COUNT: &[u8] = b"settlement-pending-count:v1";

pub(super) struct Settlement {
    config: SettlementConfig,
    issuer: Issuer,
    verifier: cmbl::settlement::Verifier,
    binding: [u8; 32],
    context: [u8; 32],
    incarnation: String,
    community: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mode {
    format: String,
    period_seconds: u64,
    pending_capacity: u32,
    issuance_members_capacity: u32,
    binding: [u8; 32],
    epoch: u64,
    context: [u8; 32],
    key_count: u32,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerAnchor {
    format: String,
    descriptor: cmbl::settlement::Epoch,
    policy_epoch: u64,
    quota: u16,
    incarnation: String,
    issued: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifiedDepositFact {
    format: String,
    deposit: crate::extensions::Deposit,
    binding: [u8; 32],
    eligible_epoch: u64,
}

fn binding(extensions: &Extensions) -> Result<[u8; 32], Error> {
    let bytes = serde_json::to_vec(&(
        "cblc.settlement.native-binding.v1",
        &extensions.config,
        &extensions.artifact_binding.manifest_sha256,
        extensions.artifact_binding.certificate_key.as_slice(),
    ))
    .map_err(|_| Error::Storage)?;
    Ok(Sha256::digest(bytes).into())
}
fn scoped_key(prefix: &[u8], pieces: &[&[u8]]) -> Vec<u8> {
    let mut bytes = prefix.to_vec();
    for piece in pieces {
        bytes.extend_from_slice(piece);
    }
    bytes
}
fn prefix_end(prefix: &[u8]) -> Result<Vec<u8>, Error> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last != 255 {
            end.push(last + 1);
            return Ok(end);
        }
    }
    Err(Error::Storage)
}
fn epoch_key(epoch: u64) -> Vec<u8> {
    scoped_key(ANCHOR_PREFIX, &[&epoch.to_be_bytes()])
}
fn fact_key(epoch: u64, nullifier: &[u8; 32]) -> Vec<u8> {
    scoped_key(FACT_PREFIX, &[&epoch.to_be_bytes(), nullifier])
}

pub(super) fn legacy_fence(tx: &mut Transaction<'_>) -> Result<(), Error> {
    if tx.get::<Mode>(MODE)?.is_some() {
        return Err(Error::UnsupportedCapability);
    }
    // Preserve the original scalar-only legacy port. The configured daily
    // constructor additionally requires the complete bounded namespace scan;
    // that constructor never falls back to a legacy handle after corruption.
    if tx.get::<u32>(COUNT)?.is_some() {
        return Err(Error::Storage);
    }
    Ok(())
}

fn check_mode(tx: &mut Transaction<'_>, settlement: &Settlement) -> Result<(), Error> {
    let mode: Mode = tx.get(MODE)?.ok_or(Error::Storage)?;
    if mode.format != "cblc.settlement.mode.v2"
        || mode.binding != settlement.binding
        || mode.period_seconds != settlement.config.period_seconds
        || mode.pending_capacity != settlement.config.pending_capacity
        || mode.issuance_members_capacity != settlement.config.issuance_members_capacity
        || mode.epoch != settlement.config.epoch.epoch
        || mode.context != settlement.context
    {
        return Err(Error::PolicyMismatch);
    }
    keys::history(tx, mode.key_count, mode.epoch, settlement)?;
    Ok(())
}
fn anchor(tx: &mut Transaction<'_>, settlement: &Settlement) -> Result<IssuerAnchor, Error> {
    check_mode(tx, settlement)?;
    let anchor: IssuerAnchor = tx
        .get(&epoch_key(settlement.config.epoch.epoch))?
        .ok_or(Error::Storage)?;
    if anchor.format != "cblc.settlement.issuer.v1"
        || anchor.descriptor != settlement.config.epoch
        || anchor.policy_epoch != settlement.config.policy_epoch
        || anchor.quota != settlement.config.quota
        || anchor.incarnation != settlement.incarnation
        || anchor.issued > MAX_INTEGER
    {
        return Err(Error::PolicyMismatch);
    }
    keys::check(tx, &anchor.descriptor)?;
    Ok(anchor)
}

#[cfg(feature = "publication")]
pub(super) fn public_settings(
    tx: &mut Transaction<'_>,
    settlement: Option<&Settlement>,
    policy_epoch: u64,
) -> Result<Option<crate::settlement::SettlementCapability>, Error> {
    match (tx.get::<Mode>(MODE)?, settlement) {
        (None, None) => {
            legacy_fence(tx)?;
            Ok(None)
        }
        (None, Some(_)) => Err(Error::Storage),
        (Some(_), None) => Err(Error::UnsupportedCapability),
        (Some(_), Some(settlement)) => {
            anchor(tx, settlement)?;
            let settings = crate::settlement::SettlementCapability {
                epoch: settlement.config.epoch.clone(),
                policy_epoch: settlement.config.policy_epoch,
                period_seconds: settlement.config.period_seconds,
                quota: settlement.config.quota,
            };
            settings.validate(&settlement.config.epoch.community, policy_epoch)?;
            Ok(Some(settings))
        }
    }
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Install the original provisioned outcome-only key and immutable daily
    /// mode. The host must hold current Policy/configuration authority across
    /// this call; no request may select this configuration or private key.
    /// Reopen preserves the exact anchor, allowance and pending facts. A lost
    /// key or altered same-epoch descriptor never resets the epoch's budget.
    pub fn with_daily_settlement(
        mut self,
        config: SettlementConfig,
        provisioned_key: &[u8],
        incarnation: String,
        clock: impl Fn() -> u64,
    ) -> Result<Self, Error> {
        self.activate_daily_settlement(config, provisioned_key, incarnation, clock)?;
        Ok(self)
    }

    /// Renew the common epoch on this SAME ledger and worker; no account,
    /// pending-fact or earlier allowance state is recreated. The caller must
    /// reconcile uncertain commits before exposing the renewed descriptor.
    pub fn activate_daily_settlement(
        &mut self,
        config: SettlementConfig,
        provisioned_key: &[u8],
        incarnation: String,
        clock: impl Fn() -> u64,
    ) -> Result<cmbl::settlement::Epoch, Error> {
        self.install_daily_settlement(
            config,
            KeySource::Encoded(provisioned_key),
            incarnation,
            clock,
            None,
        )
    }

    /// Reopen/catch up only to the independently held current Policy. The real
    /// owner is checked inside the existing native writer, including initial
    /// installation and exact retries. No member DTO selects this operation.
    /// A same-day advance changes effective authority, never the common key,
    /// quota, receipt fingerprint, issued total or replay namespace.
    pub fn reconcile_daily_settlement(
        &mut self,
        config: SettlementConfig,
        provisioned_key: &[u8],
        incarnation: String,
        authority: Arc<dyn crate::storage::CommitAuthority>,
        clock: impl Fn() -> u64,
    ) -> Result<cmbl::settlement::Epoch, Error> {
        self.install_daily_settlement(
            config,
            KeySource::Encoded(provisioned_key),
            incarnation,
            clock,
            Some(authority),
        )
    }

    /// Queue the original opaque provisioned issuer without retaining raw DER.
    /// Its exact public epoch must agree with independently configured Policy
    /// data; the actual Policy callback still gates the native writer decision.
    pub fn reconcile_daily_settlement_with_issuer(
        &mut self,
        config: SettlementConfig,
        issuer: Issuer,
        incarnation: String,
        authority: Arc<dyn crate::storage::CommitAuthority>,
        clock: impl Fn() -> u64,
    ) -> Result<cmbl::settlement::Epoch, Error> {
        self.install_daily_settlement(
            config,
            KeySource::Issuer(issuer),
            incarnation,
            clock,
            Some(authority),
        )
    }

    /// A cold owner remains quarantined until the real current Policy callback
    /// acknowledges this exact native configuration and any monotonic advance.
    pub fn with_reconciled_daily_settlement(
        mut self,
        config: SettlementConfig,
        provisioned_key: &[u8],
        incarnation: String,
        authority: Arc<dyn crate::storage::CommitAuthority>,
        clock: impl Fn() -> u64,
    ) -> Result<Self, Error> {
        self.reconcile_daily_settlement(config, provisioned_key, incarnation, authority, clock)?;
        Ok(self)
    }

    fn install_daily_settlement(
        &mut self,
        config: SettlementConfig,
        provisioned: KeySource<'_>,
        incarnation: String,
        clock: impl Fn() -> u64,
        authority: Option<Arc<dyn crate::storage::CommitAuthority>>,
    ) -> Result<cmbl::settlement::Epoch, Error> {
        let _current = authority
            .as_ref()
            .map(|owner| self.authority.enter(owner.clone()))
            .transpose()?;
        eprintln!("DIAG community cfg={} ledger={} ctx_err={:?} pe={} per={} q={} pc={} im={} rooms={}", config.epoch.community, self.trust.community_id, config.epoch.context().err(), config.policy_epoch, config.period_seconds, config.quota, config.pending_capacity, config.issuance_members_capacity, config.room_epochs.len());
        config.validate(&self.trust.community_id)?;
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        // Never activate an ingress queue whose configured native owner cannot
        // publish its genuine G2 cut. The legacy three-key group stays partial.
        extensions.verifier.require_record_epoch()?;
        let binding = binding(extensions)?;
        let context = config.epoch.context().map_err(|e| {eprintln!("DIAG context {e:?}"); crypto_error(e)})?;
        let issuer = match provisioned {
            KeySource::Encoded(bytes) => {
                Issuer::from_pkcs1_der(config.epoch.clone(), bytes).map_err(|e| {eprintln!("DIAG issuer from_pkcs1_der {e:?}"); crypto_error(e)})?
            }
            KeySource::Issuer(issuer) => {
                if issuer.epoch() != &config.epoch {
                    return Err(Error::PolicyMismatch);
                }
                issuer
            }
        };
        let verifier = cmbl::settlement::Verifier::new(config.epoch.clone(), incarnation.clone())
            .map_err(crypto_error)?;
        let settlement = Settlement {
            config,
            issuer,
            verifier,
            binding,
            context,
            incarnation,
            community: self.community,
        };
        let clock = observed_clock(self.observed_time.clone(), clock);
        let before = clock();
        check_time(before, 0)?;
        let mut tx = self.connection.transaction()?;
        let now = clock();
        check_time(now, before.max(clock_floor(&mut tx)?))?;
        check_config(&mut tx, &self.config)?;
        check_extension_config(&mut tx, Some(extensions))?;
        if now / settlement.config.period_seconds != settlement.config.epoch.epoch {
            return Err(Error::Expired);
        }
        let prior: Option<Mode> = tx.get(MODE)?;
        if let Some(prior) = &prior {
            if prior.format != "cblc.settlement.mode.v2"
                || prior.binding != binding
                || prior.period_seconds != settlement.config.period_seconds
                || prior.pending_capacity != settlement.config.pending_capacity
                || prior.issuance_members_capacity != settlement.config.issuance_members_capacity
            {
                return Err(Error::PolicyMismatch);
            }
            keys::history(&mut tx, prior.key_count, prior.epoch, &settlement)?;
            if prior.epoch > settlement.config.epoch.epoch {
                return Err(Error::ClockRollback);
            }
            if prior.epoch == settlement.config.epoch.epoch {
                if prior.context != context {
                    return Err(Error::PolicyMismatch);
                }
                let mut installed: IssuerAnchor =
                    tx.get(&epoch_key(prior.epoch))?.ok_or(Error::Storage)?;
                if installed.format != "cblc.settlement.issuer.v1"
                    || installed.descriptor != settlement.config.epoch
                    || installed.quota != settlement.config.quota
                    || installed.incarnation != settlement.incarnation
                    || installed.policy_epoch == 0
                    || installed.policy_epoch > MAX_INTEGER
                    || installed.issued > MAX_INTEGER
                {
                    return Err(Error::PolicyMismatch);
                }
                keys::check(&mut tx, &installed.descriptor)?;
                if installed.policy_epoch > settlement.config.policy_epoch {
                    return Err(Error::ClockRollback);
                }
                if installed.policy_epoch != settlement.config.policy_epoch {
                    // Only the typed retained owner can authorize this advance.
                    // Its actual check runs at commit_record under THIS writer.
                    authority.as_ref().ok_or(Error::Admission)?;
                    issuance::budgets(&mut tx, &settlement, &installed)?;
                    installed.policy_epoch = settlement.config.policy_epoch;
                    tx.put(&epoch_key(prior.epoch), &installed)?;
                } else {
                    anchor(&mut tx, &settlement)?;
                }
            } else {
                let old: IssuerAnchor = tx.get(&epoch_key(prior.epoch))?.ok_or(Error::Storage)?;
                if old.format != "cblc.settlement.issuer.v1"
                    || old.descriptor.epoch != prior.epoch
                    || old.descriptor.context().map_err(crypto_error)? != prior.context
                    || old.descriptor.public_key_der == settlement.config.epoch.public_key_der
                {
                    return Err(Error::PolicyMismatch);
                }
                keys::check(&mut tx, &old.descriptor)?;
            }
        } else {
            // An orphan namespace cannot be interpreted as a fresh activation.
            let rows: Vec<(Vec<u8>, serde_json::Value)> =
                tx.current_range(b"settlement-", &prefix_end(b"settlement-")?, 1)?;
            if !rows.is_empty() {
                return Err(Error::Storage);
            }
            if clock_floor(&mut tx)? != 0 {
                return Err(Error::Storage);
            }
            let accounts: Vec<(Vec<u8>, Frontier)> = tx.current_range(&[1], &[2], 1)?;
            if !accounts.is_empty() {
                return Err(Error::Storage);
            }
        }
        // Any earlier use of this RSA key binds it to that original context.
        // Hidden blind messages cannot be restricted to the advertised epoch.
        let key_count = keys::install(
            &mut tx,
            &settlement.config.epoch,
            prior.as_ref().map_or(0, |mode| mode.key_count),
        )?;
        let existing: Option<IssuerAnchor> = tx.get(&epoch_key(settlement.config.epoch.epoch))?;
        if prior
            .as_ref()
            .is_none_or(|m| m.epoch != settlement.config.epoch.epoch)
        {
            if existing.is_some() {
                return Err(Error::Storage);
            }
            tx.put(
                &epoch_key(settlement.config.epoch.epoch),
                &IssuerAnchor {
                    format: "cblc.settlement.issuer.v1".into(),
                    descriptor: settlement.config.epoch.clone(),
                    policy_epoch: settlement.config.policy_epoch,
                    quota: settlement.config.quota,
                    incarnation: settlement.incarnation.clone(),
                    issued: 0,
                },
            )?;
        }
        tx.put(
            MODE,
            &Mode {
                format: "cblc.settlement.mode.v2".into(),
                period_seconds: settlement.config.period_seconds,
                pending_capacity: settlement.config.pending_capacity,
                issuance_members_capacity: settlement.config.issuance_members_capacity,
                binding,
                epoch: settlement.config.epoch.epoch,
                context,
                key_count,
            },
        )?;
        if prior.is_none() {
            tx.put(COUNT, &0u32)?;
        }
        tx.commit_before(&CommitDeadline::new(
            &clock,
            now,
            settlement.config.expires_at(),
        ))?;
        let returned = clock();
        if check_time(returned, now).is_err() || returned >= settlement.config.expires_at() {
            return Err(Error::Storage);
        }
        let descriptor = settlement.config.epoch.clone();
        self.settlement = Some(settlement);
        Ok(descriptor)
    }
}
