//! Atomic extension operations. Only the configured backend can authorize effects.
use super::*;
use crate::extensions::{
    self, Deposit, ExtendedUpdate, ExtensionPolicy, ExtensionStatement, ExtensionVerifier,
    Extensions, Inbox, PendingObligation, PublicRecord,
};

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Certify a genuinely issued extension acceptance for an anonymous deposit.
    /// The independent P-256 issuer key must match the pinned verifier manifest.
    /// Only an acceptance returned after the atomic commit can pass this check.
    pub fn certify_extended(
        &self,
        accepted: &AccountAcceptance,
        issuer: &cssr::certificate::CertificateIssuer,
    ) -> Result<crate::extensions::StateCertificate, Error> {
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        verify_account_acceptance(accepted, &self.operator.verifying_key().to_bytes())?;
        if accepted.statement.community != self.community
            || accepted.proof_scope != extensions.verifier.scope()
        {
            return Err(Error::PolicyMismatch);
        }
        let signature = issuer.issue(&cssr::certificate::AcceptedState {
            community: self.community,
            owner: accepted.statement.owner,
            state: accepted.statement.next_state,
            scope: accepted.proof_scope.circuit_digest,
            version: accepted.statement.next_version,
            accepted_at: accepted.accepted_at,
        });
        Ok(crate::extensions::StateCertificate {
            accepted_at: accepted.accepted_at,
            signature: signature.to_vec(),
        })
    }
    /// Pin a separate complete extension relation. Legacy handles then fail closed.
    /// Only host configuration may call this; never accept a verifier from a request.
    pub fn with_extensions(
        mut self,
        policy: ExtensionPolicy,
        verifier: crate::verification::ProcessExtensionVerifier,
        limits: crate::verification::ExtensionLimits,
        activation: crate::extensions::ExtensionActivation,
    ) -> Result<Self, Error> {
        policy.validate()?;
        let budget = crate::verification::Budget::new(&self.trust.community_id, limits)?;
        let scope = verifier.scope();
        if scope == self.proof_scope
            || scope.circuit_digest == [0; 32]
            || scope.verifying_key_digest == [0; 32]
        {
            return Err(Error::PolicyMismatch);
        }
        if self.policy.max_proof_bytes < extensions::EXTENSION_PROOF_BYTES
            || !activation.account.genesis
            || activation.account.community != self.community
            || activation.account.policy != self.policy.account
            || activation.proof.is_empty()
            || activation.proof.len() > self.policy.max_proof_bytes
        {
            return Err(Error::InvalidInput);
        }
        crate::accounting::statement_bytes(&activation.account)?;
        verifier.verify(
            &ExtensionStatement::Update {
                policy: policy.clone(),
                account: Box::new(activation.account),
                update: ExtendedUpdate {
                    previous_inbox: Inbox::default(),
                    inbox: Inbox::default(),
                    effect: crate::extensions::Effect::Update,
                },
            },
            &activation.proof,
        )?;
        let config =
            serde_json::to_vec(&(policy.clone(), &scope)).map_err(|_| Error::InvalidInput)?;
        let mut tx = self.connection.transaction()?;
        let old: Option<Vec<u8>> = tx.get(b"extensions")?;
        if old.as_ref().is_some_and(|v| v != &config) {
            return Err(Error::PolicyMismatch);
        }
        tx.put(b"extensions", &config)?;
        tx.commit()?;
        self.extensions = Some(Extensions {
            policy,
            budget,
            verifier: Box::new(verifier),
            config,
        });
        Ok(self)
    }

    /// Verify the full extended account relation and consume the exact inbox frontier.
    pub fn apply_extended(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &AccountRequest,
        update: &ExtendedUpdate,
        clock: impl Fn() -> u64,
    ) -> Result<AccountAcceptance, Error> {
        self.apply_inner(grant, authorization, request, Some(update), clock)
    }

    /// Accept a delayed batch of anonymous settlements. Every outcome uses the
    /// same envelope; there is no punishment-specific request or response.
    /// A relay must mix transport ingress; batching cannot hide network metadata.
    pub fn deposit_batch(
        &mut self,
        batch: &[(Deposit, Vec<u8>)],
        clock: impl Fn() -> u64,
    ) -> Result<(), Error> {
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        if batch.len() < usize::from(extensions.policy.minimum_deposit_batch) || batch.len() > 64 {
            return Err(Error::InvalidInput);
        }
        let now = clock();
        check_time(now, 0)?;
        let mut seen = std::collections::BTreeSet::new();
        for (deposit, proof) in batch {
            if deposit.community != self.community
                || [
                    deposit.recipient,
                    deposit.nullifier,
                    deposit.authorization_nullifier,
                    deposit.obligation,
                ]
                .contains(&[0; 32])
                || !seen.insert(deposit.nullifier)
                || deposit.release_epoch > now / extensions.policy.deposit_delay_seconds
                || deposit.release_epoch == 0
                || proof.is_empty()
                || proof.len() > self.policy.max_proof_bytes
            {
                return Err(Error::InvalidInput);
            }
        }
        // All cheap state/replay checks precede any expensive verification.
        let mut tx = self.connection.transaction()?;
        check_extension_config(&mut tx, Some(extensions))?;
        let mut fresh = Vec::new();
        for (deposit, _) in batch {
            fresh.push(check_deposit(&mut tx, deposit)?);
        }
        tx.rollback()?;
        for ((deposit, proof), fresh) in batch.iter().zip(&fresh) {
            if *fresh {
                extensions.budget.check(&deposit.recipient)?;
                extensions.verifier.verify_anonymous(
                    &ExtensionStatement::Deposit {
                        policy: extensions.policy.clone(),
                        deposit: deposit.clone(),
                    },
                    proof,
                )?;
            }
        }
        let completed = clock();
        check_time(completed, now)?;
        let mut tx = self.connection.transaction()?;
        check_extension_config(&mut tx, Some(extensions))?;
        for (deposit, _) in batch {
            if !check_deposit(&mut tx, deposit)? {
                continue;
            }
            let previous = extensions::inbox(&mut tx, &deposit.recipient)?;
            let next = extensions::advance(&previous, deposit)?;
            let count_key = key(10, &[&deposit.recipient]);
            let count: u8 = tx.get(&count_key)?.unwrap_or(0);
            if count >= 64 {
                return Err(Error::Capacity);
            }
            tx.put(&count_key, &(count + 1))?;
            tx.put(&key(8, &[&deposit.nullifier]), &deposit_digest(deposit)?)?;
            tx.put(&key(9, &[&deposit.authorization_nullifier]), &true)?;
            tx.put(
                &key(6, &[&deposit.recipient, &next.root]),
                &PendingObligation {
                    previous,
                    commitment: deposit.obligation,
                },
            )?;
            tx.put(&key(5, &[&deposit.recipient]), &next)?;
        }
        tx.commit()
    }

    /// Required gate for every first contact and every forum listing. A missing
    /// record or below-quorum claim without a proof cannot authorize either action.
    /// The caller supplies its expected context, independently of member input.
    pub fn check_record(
        &mut self,
        owner: [u8; 32],
        expected: &crate::extensions::RecordContext,
        record: &PublicRecord,
        proof: &[u8],
        clock: impl Fn() -> u64,
    ) -> Result<Option<[u16; 3]>, Error> {
        let now = clock();
        check_time(now, 0)?;
        if record.owner != owner || record.context != *expected || expected.challenge == [0; 32] {
            return Err(Error::Admission);
        }
        if expected.expires_at <= now
            || expected.expires_at > now.saturating_add(self.policy.max_authorization_seconds)
        {
            return Err(Error::Expired);
        }
        let result = self.public_record(record, proof)?;
        let completed = clock();
        check_time(completed, now)?;
        if completed >= expected.expires_at {
            return Err(Error::Expired);
        }
        Ok(result)
    }

    /// A pure proof check against current state. It records no display/request history.
    /// Stale records and unconsumed obligations are rejected before and after verification.
    pub(crate) fn public_record(
        &mut self,
        record: &PublicRecord,
        proof: &[u8],
    ) -> Result<Option<[u16; 3]>, Error> {
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        if record.community != self.community
            || proof.is_empty()
            || proof.len() > self.policy.max_proof_bytes
            || record
                .shares
                .is_some_and(|s| s.into_iter().map(u32::from).sum::<u32>() != 10_000)
        {
            return Err(Error::InvalidInput);
        }
        let check = |tx: &mut Transaction<'_>| -> Result<(), Error> {
            check_extension_config(tx, Some(extensions))?;
            let current: Frontier = tx.get(&key(1, &[&record.owner]))?.ok_or(Error::Admission)?;
            if current.version != record.version
                || current.state != record.state
                || extensions::inbox(tx, &record.owner)? != record.inbox
                || extensions::applied(tx, &record.owner)? != record.inbox
            {
                return Err(Error::Replay);
            }
            Ok(())
        };
        let mut tx = self.connection.transaction()?;
        check(&mut tx)?;
        tx.rollback()?;
        extensions.budget.check(&record.owner)?;
        extensions.verifier.verify_anonymous(
            &ExtensionStatement::Record {
                policy: extensions.policy.clone(),
                record: record.clone(),
            },
            proof,
        )?;
        let mut tx = self.connection.transaction()?;
        check(&mut tx)?;
        tx.rollback()?;
        Ok(record.shares)
    }

    /// Read opaque obligation commitments for an already authorized account.
    /// The service must authenticate the owner (as for status) before invoking it.
    /// Results are bounded and accessed with exact keys, never table scans.
    pub fn obligations(
        &mut self,
        owner: [u8; 32],
    ) -> Result<(Inbox, Vec<PendingObligation>), Error> {
        let mut tx = self.connection.transaction()?;
        let frontier = extensions::inbox(&mut tx, &owner)?;
        let applied = extensions::applied(&mut tx, &owner)?;
        let mut cursor = frontier.clone();
        let mut values = Vec::new();
        while cursor != applied {
            if values.len() >= 64 {
                return Err(Error::Capacity);
            }
            let value: PendingObligation = tx
                .get(&key(6, &[&owner, &cursor.root]))?
                .ok_or(Error::Storage)?;
            cursor = value.previous.clone();
            values.push(value);
        }
        values.reverse();
        tx.rollback()?;
        Ok((frontier, values))
    }
}

pub(super) fn check_extension_config(
    tx: &mut Transaction<'_>,
    configured: Option<&Extensions>,
) -> Result<(), Error> {
    let stored: Option<Vec<u8>> = tx.get(b"extensions")?;
    if stored.as_deref() != configured.map(|e| e.config.as_slice()) {
        return Err(Error::UnsupportedCapability);
    }
    Ok(())
}

fn deposit_digest(deposit: &Deposit) -> Result<[u8; 32], Error> {
    Ok(Sha256::digest(serde_json::to_vec(deposit).map_err(|_| Error::InvalidInput)?).into())
}
fn check_deposit(tx: &mut Transaction<'_>, deposit: &Deposit) -> Result<bool, Error> {
    if tx
        .get::<Frontier>(&key(1, &[&deposit.recipient]))?
        .is_none()
    {
        return Err(Error::Admission);
    }
    if let Some(stored) = tx.get::<[u8; 32]>(&key(8, &[&deposit.nullifier]))? {
        return if stored == deposit_digest(deposit)? {
            Ok(false)
        } else {
            Err(Error::Replay)
        };
    }
    if tx
        .get::<bool>(&key(9, &[&deposit.authorization_nullifier]))?
        .is_some()
    {
        return Err(Error::Replay);
    }
    if tx.get::<u8>(&key(10, &[&deposit.recipient]))?.unwrap_or(0) >= 64 {
        return Err(Error::Capacity);
    }
    Ok(true)
}

pub(super) fn consume(
    tx: &mut Transaction<'_>,
    owner: &[u8; 32],
    update: &ExtendedUpdate,
) -> Result<(), Error> {
    let mut cursor = update.inbox.clone();
    let mut count = 0;
    while cursor != update.previous_inbox {
        if count >= 64 {
            return Err(Error::Capacity);
        }
        let entry_key = key(6, &[owner, &cursor.root]);
        let pending: PendingObligation = tx.get(&entry_key)?.ok_or(Error::Storage)?;
        tx.delete(&entry_key)?;
        cursor = pending.previous;
        count += 1;
    }
    tx.delete(&key(10, &[owner]))?;
    tx.put(&key(7, &[owner]), &update.inbox)
}
