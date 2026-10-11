//! Actual committed native proof, including a receipt after its request expires.
use cblc::{
    accounting::{AccountProofVerifier, account_acceptance_bytes},
    accounting_ledger::AccountLedger,
    extensions::{ExtensionPolicy, extended_request_digest},
    pins::{SpentChange, VerifiedPinChange},
};
use cpns::server::Change;
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};

pub fn exercise<V: AccountProofVerifier>(
    ledger: &mut AccountLedger<V>,
    change: &Change<'_>,
    spent: &SpentChange,
    policy: &ExtensionPolicy,
) -> VerifiedPinChange {
    // The request itself has expired. Its genuine original acceptance still
    // proves the completed spend; it cannot be submitted as another spend.
    let now = spent.request.expires_at;
    let verified = ledger
        .verify_completed_pin_change(change, spent, || now)
        .unwrap();
    verified.check_change(change).unwrap();
    let mut wrong_revision = change.expected;
    wrong_revision.revision += 1;
    assert!(
        verified
            .check_change(&Change {
                expected: wrong_revision,
                ..*change
            })
            .is_err()
    );
    assert!(
        ledger
            .verify_completed_pin_change(
                &Change {
                    field: "location",
                    ..*change
                },
                spent,
                || now
            )
            .is_err()
    );

    // A valid operator signature alone cannot manufacture the native effect.
    // Re-sign the exact changed proof digest with the actual fixture operator.
    let mut damaged = SpentChange {
        acceptance: spent.acceptance.clone(),
        request: spent.request.clone(),
        update: spent.update.clone(),
    };
    damaged.request.proof.fill(0);
    damaged.acceptance.request_digest =
        extended_request_digest(&damaged.request, &damaged.update, policy).unwrap();
    damaged.acceptance.signature = BASE64URL_NOPAD.encode(
        &SigningKey::from_bytes(&[9; 32])
            .sign(&account_acceptance_bytes(&damaged.acceptance).unwrap())
            .to_bytes(),
    );
    assert!(
        ledger
            .verify_completed_pin_change(change, &damaged, || now)
            .is_err()
    );
    let mut wrong_policy = SpentChange {
        acceptance: spent.acceptance.clone(),
        request: spent.request.clone(),
        update: spent.update.clone(),
    };
    wrong_policy.request.statement.policy.initial_credit -= 1;
    assert!(
        ledger
            .verify_completed_pin_change(change, &wrong_policy, || now)
            .is_err()
    );
    // The one original mutable economic field does not invalidate a completed
    // permission. Exercise the real durable owner tuning, then restore its
    // value for the remaining public proof scenarios without resetting revision.
    let original = ledger.waiting_period().unwrap();
    let tuned = ledger
        .update_waiting_period(original.revision, original.seconds + 1, || now)
        .unwrap();
    ledger
        .verify_completed_pin_change(change, spent, || now)
        .unwrap()
        .check_change(change)
        .unwrap();
    ledger
        .update_waiting_period(tuned.revision, original.seconds, || now)
        .unwrap();
    verified
}
