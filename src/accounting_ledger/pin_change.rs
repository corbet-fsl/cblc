//! Historical completed-spend verification under the original activated relation.
use super::{extension_activation::ActivationAnchor, *};
use crate::{
    extensions::{Effect, verify_extended_acceptance},
    pins::{SpentChange, VerifiedPinChange, change_binding, owner},
};
use cpns::server::Change;

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Reverify the exact committed native proof before another owner consumes
    /// its pin permission. Expired request windows are historical here: the
    /// signed acceptance proves a commit inside that original window. This
    /// method neither submits a new spend nor extends current member authority.
    pub fn verify_completed_pin_change(
        &mut self,
        change: &Change<'_>,
        spent: &SpentChange,
        clock: impl Fn() -> u64,
    ) -> Result<VerifiedPinChange, Error> {
        let clock = observed_clock(self.observed_time.clone(), clock);
        let binding = change_binding(change)?;
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let request = &spent.request;
        let mut historical = request.statement.policy.clone();
        // Only the original durable waiting-period tuning may differ. The
        // actual operator acceptance below authenticates that historical value.
        historical.abandon_after = self.policy.account.abandon_after;
        if change.community != self.trust.community_id
            || request.statement.community != self.community
            || request.statement.owner != owner(change.member)?
            || request.statement.genesis
            || request.proof_scope != extensions.verifier.scope()
            || historical != self.policy.account
            || spent.update.effect != (Effect::Change { binding })
            || request.proof.is_empty()
            || request.proof.len() > self.policy.max_proof_bytes
            || spent.acceptance.accepted_at < request.issued_at
            || spent.acceptance.accepted_at >= request.expires_at
        {
            return Err(Error::PolicyMismatch);
        }
        verify_extended_acceptance(
            &spent.acceptance,
            request,
            &spent.update,
            &extensions.policy,
            &self.operator.verifying_key().to_bytes(),
        )?;
        let before = clock();
        check_time(before, spent.acceptance.accepted_at)?;
        let check = |tx: &mut Transaction<'_>, now| -> Result<(), Error> {
            check_time(now, clock_floor(tx)?.max(before))?;
            check_config(tx, &self.config)?;
            check_extension_config(tx, Some(extensions))?;
            let anchor: ActivationAnchor =
                tx.get(b"extension-activation")?.ok_or(Error::Storage)?;
            if serde_json::to_vec(&anchor).map_err(|_| Error::Storage)?
                != extensions.activation_anchor
            {
                return Err(Error::PolicyMismatch);
            }
            Ok(())
        };
        let mut tx = self.connection.transaction()?;
        check(&mut tx, clock())?;
        tx.rollback()?;
        extensions.budget.check(&request.statement.owner)?;
        extensions.verifier.verify(
            &ExtensionStatement::Update {
                policy: extensions.policy.clone(),
                account: Box::new(request.statement.clone()),
                update: spent.update.clone(),
            },
            &request.proof,
        )?;
        let mut tx = self.connection.transaction()?;
        check(&mut tx, clock())?;
        tx.rollback()?;
        check_time(clock(), before)?;
        Ok(VerifiedPinChange::new(binding))
    }
}
