//! Counterpart verification of the retained real wave and Answer proofs through
//! cwlt's `WaveVerifier` and the native worker: the proofs were produced by the
//! `proof-fixtures` job and are addressed by their digest.
#![allow(dead_code)]
mod common;
use common::wave::load;
use cwlt::wave::{VerifiedWaveOutcome, WaveContext, WaveOutcome};
use futures::executor::block_on;

#[test]
fn the_retained_reservation_and_answer_verify_natively_and_refuse_any_change() {
    let l = load();
    let (statement, proof) = &l.reservation;
    let expected: WaveContext = statement.context.clone();
    let verified = block_on(l.verifier.verify(statement, proof, &expected, l.now)).unwrap();
    assert_eq!(verified.context(), &expected);
    // A single flipped proof byte, another context or another statement field is refused.
    let mut broken = proof.clone();
    broken[40] ^= 1;
    assert!(block_on(l.verifier.verify(statement, &broken, &expected, l.now)).is_err());
    let mut other = expected.clone();
    other.nonce[0] ^= 1;
    assert!(block_on(l.verifier.verify(statement, proof, &other, l.now)).is_err());
    let mut changed = statement.clone();
    changed.binding[0] ^= 1;
    assert!(block_on(l.verifier.verify(&changed, proof, &expected, l.now)).is_err());
    let (settled, proof) = &l.outcome;
    let expected: WaveContext = settled.evidence.context.clone();
    let done: VerifiedWaveOutcome = block_on(l.verifier.verify_outcome(
        settled,
        proof,
        &expected,
        WaveOutcome::Answer,
        &settled.receipt_digest,
        l.now,
    ))
    .unwrap();
    assert_eq!(done.outcome(), WaveOutcome::Answer);
    // The reservation proof is not an outcome proof, and a Close was never proved.
    assert!(
        block_on(l.verifier.verify_outcome(
            settled,
            &l.reservation.1,
            &expected,
            WaveOutcome::Answer,
            &settled.receipt_digest,
            l.now
        ))
        .is_err()
    );
    assert!(
        block_on(l.verifier.verify_outcome(
            settled,
            proof,
            &expected,
            WaveOutcome::Close,
            &settled.receipt_digest,
            l.now
        ))
        .is_err()
    );
}
