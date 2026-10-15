//! Domain-validated public inputs for the maintained native proof backend.
//! No private witness or application policy is interpreted by the backend.
use crate::{
    Error,
    accounting::{AccountProofScope, AccountStatement, statement_bytes},
    extensions::{
        EXTENSION_PROOF_BYTES, Effect, ExtendedUpdate, ExtensionPolicy, ExtensionStatement,
        ISSUE_UNITS, RecordUse, VoucherPurpose,
    },
};
use data_encoding::HEXLOWER;
use serde::Deserialize;

#[cfg(test)]
mod tests;

/// Canonical BN254 public scalar encoding. Values are bytes, u64s or zero-extended
/// 128-bit limbs, all below the field modulus.
pub type PublicField = [u8; 32];

fn scalar(value: u64) -> PublicField {
    let mut field = [0; 32];
    field[24..].copy_from_slice(&value.to_be_bytes());
    field
}

fn bytes(fields: &mut Vec<PublicField>, value: &[u8]) {
    fields.extend(value.iter().map(|byte| scalar(u64::from(*byte))));
}

/// Validate the existing signed account statement and encode the Noir public ABI.
pub fn account_inputs(statement: &AccountStatement) -> Result<Vec<PublicField>, Error> {
    statement_bytes(statement)?;
    Ok(account_fields(statement))
}

// Called only after validating the original statement. Intermediate ingestion
// proofs deliberately keep the same version and therefore must not be validated
// as ordinary complete account transitions a second time.
fn account_fields(s: &AccountStatement) -> Vec<PublicField> {
    let mut fields = Vec::with_capacity(243);
    for value in [&s.community, &s.owner, &s.policy_digest, &s.enrollment_root] {
        bytes(&mut fields, value);
    }
    fields.extend(
        [
            s.now,
            s.valid_until,
            u64::from(s.genesis),
            s.previous_version,
            s.next_version,
        ]
        .map(scalar),
    );
    for value in [&s.previous_state, &s.next_state, &s.settlement_marker] {
        bytes(&mut fields, value);
    }
    let p = &s.policy;
    fields.extend(
        [
            u64::from(p.initial_credit),
            u64::from(p.maximum_available),
            u64::from(p.outgoing_reservation),
            u64::from(p.incoming_reservation),
            p.policy_revision,
            p.policy_valid_from,
            p.policy_valid_until,
            p.newcomer_period,
            p.rate_window,
            u64::from(p.newcomer_admissions),
            u64::from(p.maximum_admissions),
            p.refill_period,
            u64::from(p.refill_units),
            p.abandon_after,
        ]
        .map(scalar),
    );
    fields
}

pub(crate) struct PreparedProof {
    pub inputs: Vec<PublicField>,
    pub proof: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle<T> {
    version: u8,
    proofs: Vec<T>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateStep {
    state: [u8; 32],
    inbox: [u8; 32],
    proof: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnonymousStep {
    proof: String,
}

fn bundle<T: serde::de::DeserializeOwned>(proof: &[u8]) -> Result<Bundle<T>, Error> {
    if proof.len() > EXTENSION_PROOF_BYTES {
        return Err(Error::Capacity);
    }
    let bundle: Bundle<T> = serde_json::from_slice(proof).map_err(|_| Error::InvalidInput)?;
    if bundle.version != 1 || bundle.proofs.is_empty() || bundle.proofs.len() > 65 {
        return Err(Error::InvalidInput);
    }
    Ok(bundle)
}

fn decode(proof: &str) -> Result<Vec<u8>, Error> {
    if proof.is_empty() || proof.len() > 2 * 1024 * 1024 {
        return Err(Error::InvalidInput);
    }
    HEXLOWER
        .decode(proof.as_bytes())
        .map_err(|_| Error::InvalidInput)
}

fn extension_fields(policy: &ExtensionPolicy) -> Result<Vec<PublicField>, Error> {
    policy.validate()?;
    let mut fields = [
        policy.revision,
        u64::from(policy.public_record_quorum),
        u64::from(policy.change_token_cost),
        policy.deposit_delay_seconds,
        u64::from(policy.minimum_deposit_batch),
    ]
    .map(scalar)
    .to_vec();
    bytes(&mut fields, &policy.standing_policy_digest);
    Ok(fields)
}

fn update_fields(
    policy: &ExtensionPolicy,
    account: &AccountStatement,
    previous: &[u8; 32],
    inbox: &[u8; 32],
    consume: bool,
    binding: &[u8; 32],
    voucher: (u8, [u8; 32]),
) -> Result<Vec<PublicField>, Error> {
    let mut fields = extension_fields(policy)?;
    bytes(&mut fields, previous);
    bytes(&mut fields, inbox);
    fields.push(scalar(u64::from(consume)));
    bytes(&mut fields, binding);
    fields.extend(account_fields(account));
    // Voucher accounting: the sponsor's role class and the consumed obligation tag, both
    // zero unless the final action says otherwise.
    fields.push(scalar(u64::from(voucher.0)));
    bytes(&mut fields, &voucher.1);
    Ok(fields)
}

fn update_proofs(
    policy: &ExtensionPolicy,
    account: &AccountStatement,
    update: &ExtendedUpdate,
    proof: &[u8],
) -> Result<Vec<PreparedProof>, Error> {
    statement_bytes(account)?;
    policy.validate()?;
    let bundle: Bundle<UpdateStep> = bundle(proof)?;
    let count = bundle.proofs.len();
    let mut state = account.previous_state;
    let mut inbox = update.previous_inbox.root;
    let mut prepared = Vec::with_capacity(count);
    for (index, step) in bundle.proofs.into_iter().enumerate() {
        czkp::field(&step.state, true)?;
        let mut current = account.clone();
        current.previous_state = state;
        let last = index + 1 == count;
        let (binding, voucher) = if last {
            if inbox != update.inbox.root
                || step.inbox != update.inbox.root
                || step.state != account.next_state
            {
                return Err(Error::InvalidInput);
            }
            if let Effect::Consume { obligation } = update.effect {
                czkp::field(&obligation, true)?;
                if obligation == [0; 32] {
                    return Err(Error::InvalidInput);
                }
            }
            let binding = match update.effect {
                Effect::Change { binding } => binding,
                _ => [0; 32],
            };
            (binding, update.effect.voucher_inputs())
        } else {
            if account.genesis || inbox == step.inbox {
                return Err(Error::InvalidInput);
            }
            current.next_state = step.state;
            current.next_version = account.previous_version;
            current.settlement_marker = [0; 32];
            ([0; 32], (0, [0; 32]))
        };
        let inputs = update_fields(
            policy,
            &current,
            &inbox,
            &step.inbox,
            !last,
            &binding,
            voucher,
        )?;
        prepared.push(PreparedProof {
            inputs,
            proof: decode(&step.proof)?,
        });
        state = step.state;
        inbox = step.inbox;
    }
    Ok(prepared)
}

/// The group digest is supplied only by authenticated artifacts. A deposit names its
/// issuer key period; the caller has matched it against the recorded ring first.
pub(crate) fn extension_proofs(
    statement: &ExtensionStatement,
    proof: &[u8],
    scope: &AccountProofScope,
) -> Result<Vec<PreparedProof>, Error> {
    let fields = match statement {
        ExtensionStatement::Update {
            policy,
            account,
            update,
        } => return update_proofs(policy, account, update, proof),
        ExtensionStatement::Deposit { policy, deposit } => {
            let mut fields = extension_fields(policy)?;
            if deposit.release_epoch == 0
                || deposit.release_epoch > czkp::MAX_INTEGER / policy.deposit_delay_seconds
            {
                return Err(Error::InvalidInput);
            }
            for value in [
                &deposit.nullifier,
                &deposit.authorization_nullifier,
                &deposit.obligation,
            ] {
                czkp::field(value, true)?;
            }
            let issuer: [u8; 64] = deposit
                .issuer_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidInput)?;
            if deposit.issuer_valid_from == 0
                || deposit.issuer_valid_until <= deposit.issuer_valid_from
                || deposit.issuer_valid_until > czkp::MAX_INTEGER
                || deposit.identity == [0; 32]
            {
                return Err(Error::InvalidInput);
            }
            bytes(&mut fields, &issuer);
            fields.push(scalar(deposit.issuer_valid_from));
            fields.push(scalar(deposit.issuer_valid_until));
            bytes(&mut fields, &scope.circuit_digest);
            bytes(&mut fields, &deposit.community);
            bytes(&mut fields, &deposit.identity);
            bytes(&mut fields, &deposit.recipient);
            fields.push(scalar(deposit.release_epoch));
            for value in [
                &deposit.nullifier,
                &deposit.authorization_nullifier,
                &deposit.obligation,
            ] {
                bytes(&mut fields, value);
            }
            fields
        }
        ExtensionStatement::Record { policy, record } => {
            let mut fields = extension_fields(policy)?;
            if record.version > czkp::MAX_INTEGER
                || record.context.expires_at == 0
                || record.context.expires_at > czkp::MAX_INTEGER
                || record.context.challenge == [0; 32]
            {
                return Err(Error::InvalidInput);
            }
            czkp::field(&record.state, true)?;
            bytes(&mut fields, &record.community);
            bytes(&mut fields, &record.owner);
            fields.push(scalar(record.version));
            bytes(&mut fields, &record.state);
            bytes(&mut fields, &record.inbox.root);
            fields.push(scalar(match record.context.purpose {
                RecordUse::FirstContact => 0,
                RecordUse::ForumListing => 1,
            }));
            bytes(&mut fields, &record.context.challenge);
            fields.push(scalar(record.context.expires_at));
            fields.push(scalar(u64::from(record.shares.is_some())));
            fields.extend(
                record
                    .shares
                    .unwrap_or([0; 3])
                    .map(|share| scalar(u64::from(share))),
            );
            fields
        }
        ExtensionStatement::RecordEpoch { policy, record } => {
            let mut fields = extension_fields(policy)?;
            record.validate()?;
            let epoch = &record.epoch;
            if epoch.proof_scope != *scope {
                return Err(Error::PolicyMismatch);
            }
            // R2 binds these public bytes in the circuit; the original issuer
            // Ed25519 certificate itself must be checked natively, every time.
            // Authentication of this descriptor remains the relying owner's job.
            czkp::record::verify_certificate(
                &epoch.issuer_key,
                &epoch.community,
                epoch.epoch,
                &record.blinded_leaf,
                &record.certificate,
            )?;
            for value in [
                epoch.issuer_key.as_slice(),
                record.certificate.as_slice(),
                epoch.proof_scope.circuit_digest.as_slice(),
                epoch.proof_scope.verifying_key_digest.as_slice(),
                epoch.community.as_slice(),
                record.owner.as_slice(),
            ] {
                bytes(&mut fields, value);
            }
            fields.extend([epoch.epoch, epoch.starts_at, epoch.expires_at].map(scalar));
            bytes(&mut fields, &epoch.root);
            fields.push(scalar(u64::from(epoch.leaf_count)));
            bytes(&mut fields, &record.blinded_leaf);
            for limb in record.presentation_key.as_chunks::<16>().0 {
                let mut field = [0; 32];
                field[16..].copy_from_slice(limb);
                fields.push(field);
            }
            fields.push(scalar(u64::from(record.shares.is_some())));
            fields.extend(
                record
                    .shares
                    .unwrap_or([0; 3])
                    .map(|v| scalar(u64::from(v))),
            );
            fields
        }
        ExtensionStatement::VoucherEpoch {
            policy,
            presentation,
        } => {
            let mut fields = extension_fields(policy)?;
            presentation.validate()?;
            let epoch = &presentation.epoch;
            if epoch.proof_scope != *scope
                || epoch.epoch == 0
                || epoch.starts_at == 0
                || epoch.starts_at >= epoch.expires_at
                || epoch.root == [0; 32]
                || epoch.leaf_count == 0
                || epoch.leaf_count > czkp::record::MAX_LEAVES
            {
                return Err(Error::PolicyMismatch);
            }
            // As for the record epoch, the issuer certificate over the blinded leaf is
            // checked natively every time; the circuit binds the same public bytes.
            czkp::record::verify_certificate(
                &epoch.issuer_key,
                &epoch.community,
                epoch.epoch,
                &presentation.blinded_leaf,
                &presentation.certificate,
            )?;
            for value in [
                epoch.issuer_key.as_slice(),
                presentation.certificate.as_slice(),
                epoch.proof_scope.circuit_digest.as_slice(),
                epoch.proof_scope.verifying_key_digest.as_slice(),
                epoch.community.as_slice(),
            ] {
                bytes(&mut fields, value);
            }
            fields.extend([epoch.epoch, epoch.starts_at, epoch.expires_at].map(scalar));
            bytes(&mut fields, &epoch.root);
            fields.push(scalar(u64::from(epoch.leaf_count)));
            bytes(&mut fields, &presentation.blinded_leaf);
            let (purpose, uses, tag, signoff, nullifiers) = match &presentation.purpose {
                VoucherPurpose::Issue {
                    uses,
                    signoff_standing,
                    nullifiers,
                } => {
                    let mut padded = [[0; 32]; ISSUE_UNITS];
                    padded[..nullifiers.len()].copy_from_slice(nullifiers);
                    (0, u64::from(*uses), [0; 32], *signoff_standing, padded)
                }
                VoucherPurpose::Post { tag } => (1, 0, *tag, 0, [[0; 32]; ISSUE_UNITS]),
            };
            fields.push(scalar(purpose));
            fields.push(scalar(uses));
            fields.push(scalar(presentation.now));
            bytes(&mut fields, &tag);
            bytes(&mut fields, &presentation.binding);
            fields.push(scalar(signoff));
            // One field per nullifier slot (a Field array, not bytes).
            fields.extend(nullifiers);
            fields
        }
    };
    let bundle: Bundle<AnonymousStep> = bundle(proof)?;
    if bundle.proofs.len() != 1 {
        return Err(Error::InvalidInput);
    }
    Ok(vec![PreparedProof {
        inputs: fields,
        proof: decode(&bundle.proofs[0].proof)?,
    }])
}
