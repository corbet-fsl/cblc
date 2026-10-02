//! Durable host boundary for the experimental account-state proof relation.
//!
//! The database stores named opaque states and owner-specific markers, never a
//! peer, conversation tuple, balance or private receipt. Its trusted dependencies
//! are the configured proof verifier, independently admitted common enrollment
//! checkpoints, trusted time and durable SQLite storage. It does not establish
//! a consistent log against an equivocating operator or restore lost openings.

use crate::{
    Error,
    accounting::{
        AccountAcceptance, AccountPolicy, AccountProofScope, AccountProofVerifier, AccountRequest,
        AccountStatusRequest, AccountStatusResponse, account_acceptance_bytes,
        account_request_bytes, account_request_digest, account_status_bytes,
        account_status_response_bytes, field, verify_account_acceptance,
    },
    admission::{
        AdmissionGrant, AdmissionTrust, DeviceAuthorization, MAX_INTEGER, decode, signature,
        verify_admission, verify_device_authorization,
    },
    storage::{AccountStorage, LibsqlStore, Transaction, key},
};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

mod extensions;
mod obligations;
mod rotation;
use rotation::check_root;
pub use rotation::{RootRotation, root_rotation_bytes};
#[cfg(feature = "publication")]
mod publication;
mod tuning;
use self::extensions::check_extension_config;
use crate::extensions::{ExtendedUpdate, ExtensionStatement, Extensions};
pub use tuning::WaitingPeriodTuning;
use tuning::{StoredConfig, check_config, config_bytes};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountLedgerPolicy {
    pub account: AccountPolicy,
    pub max_authorization_seconds: u64,
    pub max_proof_bytes: usize,
    /// Common checkpoint slots have exactly this duration. Only one root can be
    /// admitted for a slot; publication is a trusted operator operation.
    pub checkpoint_period_seconds: u64,
}

impl AccountLedgerPolicy {
    /// Validate the existing host bounds and canonical economic policy.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_authorization_seconds == 0
            || self.max_authorization_seconds > MAX_INTEGER
            || self.max_proof_bytes == 0
            || self.max_proof_bytes > i32::MAX as usize
            || self.checkpoint_period_seconds == 0
            || self.checkpoint_period_seconds > MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        self.account.validate()
    }
}

pub struct AccountLedger<V: AccountProofVerifier> {
    connection: Box<dyn AccountStorage>,
    trust: AdmissionTrust,
    community: [u8; 32],
    policy: AccountLedgerPolicy,
    policy_digest: [u8; 32],
    config: Vec<u8>,
    tuning_revision: u64,
    proof_scope: AccountProofScope,
    verifier: V,
    operator: SigningKey,
    extensions: Option<Extensions>,
}

fn check_time(now: u64, floor: u64) -> Result<(), Error> {
    if now == 0 || now < floor || now > MAX_INTEGER {
        return Err(Error::ClockRollback);
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Frontier {
    root_key: [u8; 32],
    root_revision: u64,
    version: u64,
    state: [u8; 32],
    latest_request: [u8; 32],
}
fn clock_floor(tx: &mut Transaction<'_>) -> Result<u64, Error> {
    tx.get(b"clock")?.ok_or(Error::Storage)
}
fn advance_clock(tx: &mut Transaction<'_>, now: u64) -> Result<(), Error> {
    tx.put(b"clock", &now)
}
fn cached(
    tx: &mut Transaction<'_>,
    owner: &[u8; 32],
    request: &[u8; 32],
    operator_key: &[u8; 32],
) -> Result<Option<AccountAcceptance>, Error> {
    let value: Option<AccountAcceptance> = tx.get(&key(2, &[owner]))?;
    if let Some(value) = value {
        verify_account_acceptance(&value, operator_key).map_err(|_| Error::Storage)?;
        if value.statement.owner != *owner {
            return Err(Error::Storage);
        }
        if value.request_id == *request {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

// Check mutable database predicates both before expensive verification and in
// the final write transaction. Policy and request bytes remain immutably
// borrowed across verification; no preflight database result authorizes commit.
fn check_pending(
    transaction: &mut Transaction<'_>,
    request: &AccountRequest,
    grant: &AdmissionGrant,
    authorization: &DeviceAuthorization,
    policy: &AccountLedgerPolicy,
    now: u64,
    extension: Option<(&Extensions, &ExtendedUpdate)>,
) -> Result<(), Error> {
    check_extension_config(transaction, extension.map(|(e, _)| e))?;
    if let Some((_, update)) = extension
        && (crate::extensions::inbox(transaction, &request.statement.owner)? != update.inbox
            || crate::extensions::applied(transaction, &request.statement.owner)?
                != update.previous_inbox)
    {
        return Err(Error::Replay);
    }
    let statement = &request.statement;
    if request.expires_at - request.issued_at > policy.max_authorization_seconds
        || now < request.issued_at
        || now >= request.expires_at
        || request.expires_at > grant.expires_at
        || request.expires_at > authorization.expires_at
    {
        return Err(Error::Expired);
    }
    let slot = statement.now / policy.checkpoint_period_seconds;
    if now / policy.checkpoint_period_seconds != slot {
        return Err(Error::Expired);
    }
    let checkpoint: Option<Vec<u8>> = transaction.get(&key(3, &[&slot.to_be_bytes()]))?;
    if checkpoint.as_deref() != Some(statement.enrollment_root.as_slice()) {
        return Err(Error::Admission);
    }
    let prior: Option<Frontier> = transaction.get(&key(1, &[&statement.owner]))?;
    match prior {
        None if statement.genesis => {}
        Some(prior)
            if !statement.genesis
                && prior.version == statement.previous_version
                && prior.state == statement.previous_state => {}
        _ => return Err(Error::Replay),
    }
    if statement.settlement_marker != [0; 32] {
        let exists = transaction
            .get::<bool>(&key(4, &[&statement.owner, &statement.settlement_marker]))?
            .is_some();
        if exists {
            return Err(Error::Replay);
        }
    }
    Ok(())
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Immutable community bound to the ledger's admission trust and storage.
    pub fn community(&self) -> &str {
        &self.trust.community_id
    }

    pub fn open(
        path: impl AsRef<Path>,
        trust: AdmissionTrust,
        policy: AccountLedgerPolicy,
        verifier: V,
        operator: SigningKey,
    ) -> Result<Self, Error> {
        let store = LibsqlStore::local(path, &trust.community_id).map_err(|_| Error::Storage)?;
        Self::with_store(store, trust, policy, verifier, operator)
    }

    pub fn with_store(
        store: impl AccountStorage + 'static,
        trust: AdmissionTrust,
        mut policy: AccountLedgerPolicy,
        verifier: V,
        operator: SigningKey,
    ) -> Result<Self, Error> {
        let mut connection: Box<dyn AccountStorage> = Box::new(store);
        if !crate::admission::scope(&trust.community_id) {
            return Err(Error::InvalidInput);
        }
        policy.validate()?;
        decode::<32>(&trust.policy_digest)?;
        let community: [u8; 32] = Sha256::digest(trust.community_id.as_bytes()).into();
        let mut policy_digest = policy.account.digest(&community)?;
        let proof_scope = verifier.scope();
        if proof_scope.circuit_digest == [0; 32] || proof_scope.verifying_key_digest == [0; 32] {
            return Err(Error::InvalidInput);
        }
        let mut tuning_revision = 0;
        let mut config = config_bytes(
            &trust,
            &policy,
            &proof_scope,
            operator.verifying_key().to_bytes(),
            tuning_revision,
        )?;
        let mut transaction = connection.transaction()?;
        let prior: Option<Vec<u8>> = transaction.get(b"config")?;
        if let Some(prior) = prior {
            let stored: StoredConfig =
                serde_json::from_slice(&prior).map_err(|_| Error::PolicyMismatch)?;
            // The supplied wait is a bootstrap value. A restart loads the
            // durably tuned wait while every immutable setting stays pinned.
            policy.account.abandon_after = stored.policy.account.abandon_after;
            policy.account.validate()?;
            tuning_revision = stored.tuning_revision;
            if tuning_revision > MAX_INTEGER {
                return Err(Error::PolicyMismatch);
            }
            config = config_bytes(
                &trust,
                &policy,
                &proof_scope,
                operator.verifying_key().to_bytes(),
                tuning_revision,
            )?;
            if prior != config {
                return Err(Error::PolicyMismatch);
            }
            policy_digest = policy.account.digest(&community)?;
        } else {
            transaction.put(b"config", &config)?;
            transaction.put(b"clock", &0u64)?;
        }
        transaction.commit()?;
        Ok(Self {
            connection,
            trust,
            community,
            policy,
            policy_digest,
            config,
            tuning_revision,
            proof_scope,
            verifier,
            operator,
            extensions: None,
        })
    }

    /// Trusted local publication operation. The caller must have independently
    /// verified the common enrollment tree and root/device/delegation authority.
    /// Never expose this as a member-controlled endpoint or derive it from that
    /// member's proof. A signed but individually tagged root is not common.
    pub fn admit_checkpoint(&mut self, slot: u64, root: [u8; 32]) -> Result<(), Error> {
        field(&root, true)?;
        // The constructor pins a nonzero period; checked arithmetic cannot
        // produce zero here or exceed the public integer range.
        slot.checked_add(1)
            .and_then(|n| n.checked_mul(self.policy.checkpoint_period_seconds))
            .filter(|end| *end <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        let mut transaction = self.connection.transaction()?;
        let prior: Option<Vec<u8>> = transaction.get(&key(3, &[&slot.to_be_bytes()]))?;
        if let Some(prior) = prior {
            if prior.as_slice() != root {
                return Err(Error::PolicyMismatch);
            }
        } else {
            transaction.put(&key(3, &[&slot.to_be_bytes()]), &root.to_vec())?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Verify, authorize and commit one named owner update. An exact retry
    /// returns its original signed response even after the original request
    /// expires, provided the caller supplies current root/device authorization.
    pub fn apply(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &AccountRequest,
        clock: impl Fn() -> u64,
    ) -> Result<AccountAcceptance, Error> {
        self.apply_inner(grant, authorization, request, None, clock)
    }

    fn apply_inner(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &AccountRequest,
        update: Option<&ExtendedUpdate>,
        clock: impl Fn() -> u64,
    ) -> Result<AccountAcceptance, Error> {
        let extension = match update {
            Some(update) => Some((
                self.extensions
                    .as_ref()
                    .ok_or(Error::UnsupportedCapability)?,
                update,
            )),
            None => None,
        };
        let expected_scope =
            extension.map_or_else(|| self.proof_scope.clone(), |(e, _)| e.verifier.scope());
        if request.proof.len() > self.policy.max_proof_bytes {
            return Err(Error::InvalidInput);
        }
        let statement = &request.statement;
        if statement.community != self.community || request.proof_scope != expected_scope {
            return Err(Error::PolicyMismatch);
        }
        let before = clock();
        check_time(before, 0)?;
        verify_admission(grant, &self.trust, before)?;
        verify_device_authorization(authorization, grant, before)?;
        if decode::<32>(&grant.member_id)? != statement.owner
            || request.chat_public_key != grant.chat_public_key
        {
            return Err(Error::Admission);
        }
        signature(
            &request.chat_public_key,
            &account_request_bytes(request)?,
            &request.signature,
        )?;
        let request_digest = match extension {
            Some((extension, update)) => {
                crate::extensions::extended_request_digest(request, update, &extension.policy)?
            }
            None => account_request_digest(request)?,
        };
        let root_key = decode::<32>(&authorization.root_public_key)?;
        let operator_key = self.operator.verifying_key().to_bytes();
        let mut transaction = self.connection.transaction()?;
        let now = clock();
        check_time(now, clock_floor(&mut transaction)?.max(before))?;
        verify_admission(grant, &self.trust, now)?;
        verify_device_authorization(authorization, grant, now)?;
        check_extension_config(&mut transaction, extension.map(|(e, _)| e))?;
        check_root(&mut transaction, &statement.owner, &root_key)?;
        if let Some(result) = cached(
            &mut transaction,
            &statement.owner,
            &request.request_id,
            &operator_key,
        )? {
            if result.request_digest != request_digest {
                return Err(Error::Replay);
            }
            advance_clock(&mut transaction, now)?;
            transaction.commit()?;
            return Ok(result);
        }
        check_config(&mut transaction, &self.config)?;
        // statement_bytes already checks the digest of this exact policy and
        // the community was matched above. Equal policy implies equal digest.
        if statement.policy != self.policy.account {
            return Err(Error::PolicyMismatch);
        }
        check_pending(
            &mut transaction,
            request,
            grant,
            authorization,
            &self.policy,
            now,
            extension,
        )?;
        // Release every SQLite lock before invoking an external or slow
        // verifier. Other owners and competing devices can commit meanwhile.
        transaction.rollback()?;
        if let Some((extensions, update)) = extension {
            if matches!(update.effect, crate::extensions::Effect::Change { binding } if binding == [0;32])
                || (!matches!(update.effect, crate::extensions::Effect::Update)
                    && (statement.genesis || statement.settlement_marker == [0; 32]))
            {
                return Err(Error::InvalidInput);
            }
            extensions.verifier.verify(
                &ExtensionStatement::Update {
                    policy: extensions.policy.clone(),
                    account: Box::new(statement.clone()),
                    update: update.clone(),
                },
                &request.proof,
            )?;
        } else {
            self.verifier.verify(statement, &request.proof)?;
        }
        let mut transaction = self.connection.transaction()?;
        let completed = clock();
        check_time(completed, clock_floor(&mut transaction)?.max(now))?;
        if completed >= grant.expires_at || completed >= authorization.expires_at {
            return Err(Error::Expired);
        }
        verify_admission(grant, &self.trust, completed)?;
        verify_device_authorization(authorization, grant, completed)?;
        // A concurrent exact request may already have committed. Recover its
        // original response before applying expiry/CAS checks to a fresh write.
        check_extension_config(&mut transaction, extension.map(|(e, _)| e))?;
        check_root(&mut transaction, &statement.owner, &root_key)?;
        if let Some(result) = cached(
            &mut transaction,
            &statement.owner,
            &request.request_id,
            &operator_key,
        )? {
            if result.request_digest != request_digest {
                return Err(Error::Replay);
            }
            advance_clock(&mut transaction, completed)?;
            transaction.commit()?;
            return Ok(result);
        }
        check_config(&mut transaction, &self.config)?;
        // The request and this handle's policy cannot change across verification.
        // check_config above rechecks the mutable persisted configuration.
        check_pending(
            &mut transaction,
            request,
            grant,
            authorization,
            &self.policy,
            completed,
            extension,
        )?;
        let mut acceptance = AccountAcceptance {
            statement: statement.clone(),
            request_id: request.request_id,
            request_digest,
            proof_scope: expected_scope,
            accepted_at: completed,
            signature: String::new(),
        };
        acceptance.signature = BASE64URL_NOPAD.encode(
            &self
                .operator
                .sign(&account_acceptance_bytes(&acceptance)?)
                .to_bytes(),
        );
        if !statement.genesis && statement.settlement_marker != [0; 32] {
            transaction.put(
                &key(4, &[&statement.owner, &statement.settlement_marker]),
                &true,
            )?;
        }
        let root_revision = transaction
            .get::<Frontier>(&key(1, &[&statement.owner]))?
            .map_or(0, |prior| prior.root_revision);
        transaction.put(
            &key(1, &[&statement.owner]),
            &Frontier {
                root_key,
                root_revision,
                version: statement.next_version,
                state: statement.next_state,
                latest_request: request.request_id,
            },
        )?;
        if let Some((_, update)) = extension {
            extensions::consume(&mut transaction, &statement.owner, update)?;
        }
        // Replace the latest signed acceptance; no historical request table is retained.
        transaction.put(&key(2, &[&statement.owner]), &acceptance)?;
        advance_clock(&mut transaction, completed)?;
        transaction.commit()?;
        Ok(acceptance)
    }

    /// Authenticated recovery for either a specific request or the latest
    /// acceptance. This returns no private opening and grants no fresh credit.
    /// The signed response binds the fresh request challenge and observation
    /// time; a historical acceptance by itself does not attest to freshness.
    pub fn status(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &AccountStatusRequest,
        clock: impl Fn() -> u64,
    ) -> Result<AccountStatusResponse, Error> {
        let bytes = account_status_bytes(request)?;
        if request.community != self.community
            || decode::<32>(&grant.member_id)? != request.owner
            || request.chat_public_key != grant.chat_public_key
        {
            return Err(Error::Admission);
        }
        if request.expires_at - request.issued_at > self.policy.max_authorization_seconds {
            return Err(Error::Expired);
        }
        let before = clock();
        check_time(before, 0)?;
        verify_admission(grant, &self.trust, before)?;
        verify_device_authorization(authorization, grant, before)?;
        signature(&request.chat_public_key, &bytes, &request.signature)?;
        let mut transaction = self.connection.transaction()?;
        let now = clock();
        check_time(now, before.max(clock_floor(&mut transaction)?))?;
        verify_admission(grant, &self.trust, now)?;
        verify_device_authorization(authorization, grant, now)?;
        if now < request.issued_at || now >= request.expires_at {
            return Err(Error::Expired);
        }
        check_root(
            &mut transaction,
            &request.owner,
            &decode::<32>(&authorization.root_public_key)?,
        )?;
        let request_id = match request.request_id {
            Some(id) => Some(id),
            None => transaction
                .get::<Frontier>(&key(1, &[&request.owner]))?
                .map(|value| value.latest_request),
        };
        let result = request_id
            .map(|id| {
                cached(
                    &mut transaction,
                    &request.owner,
                    &id,
                    &self.operator.verifying_key().to_bytes(),
                )
            })
            .transpose()?
            .flatten();
        let mut signed_request = bytes;
        signed_request.extend_from_slice(&decode::<64>(&request.signature)?);
        let mut response = AccountStatusResponse {
            status_request_digest: Sha256::digest(signed_request).into(),
            observed_at: now,
            acceptance: result,
            signature: String::new(),
        };
        response.signature = BASE64URL_NOPAD.encode(
            &self
                .operator
                .sign(&account_status_response_bytes(&response)?)
                .to_bytes(),
        );
        advance_clock(&mut transaction, now)?;
        transaction.commit()?;
        Ok(response)
    }
}
