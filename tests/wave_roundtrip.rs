//! Counterpart verification of the retained real wave and Answer proofs through
//! cwlt's `WaveVerifier` and the native worker: the proofs were produced by the
//! `proof-fixtures` job and are addressed by their digest.
#![allow(dead_code)]
mod common;
use cblc::artifacts::{ArtifactBytes, WaveArtifacts};
use cwlt::wave::{
    ExtensionPolicy, VerifiedWaveOutcome, WaveContext, WaveOutcome, WaveOutcomeStatement,
    WavePolicy, WaveStatement, WaveVerifier,
};
use czkp::ProofScope;
use futures::executor::block_on;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Scope {
    circuit_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    kind: String,
    statement: serde_json::Value,
    proof: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    extension_scope: Scope,
    issuer_key: Vec<u8>,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    manifest_sha256: String,
}

struct Loaded {
    verifier: WaveVerifier<cvfy::NativeVerifier>,
    reservation: (WaveStatement, Vec<u8>),
    outcome: (WaveOutcomeStatement, Vec<u8>),
    now: u64,
}

fn load() -> Loaded {
    let directory = PathBuf::from(
        std::env::var_os("CBLC_WAVE_FIXTURE").expect("CI must provide the retained wave fixture"),
    );
    let text = std::fs::read(directory.join("wave-roundtrip.json")).unwrap();
    // Content addressing: the directory name is the digest of the fixture.
    assert_eq!(
        directory.file_name().unwrap().to_str().unwrap(),
        data_encoding::HEXLOWER.encode(&Sha256::digest(&text))
    );
    let fixture: Fixture = serde_json::from_slice(&text).unwrap();
    let config: Config =
        serde_json::from_slice(&std::fs::read(directory.join("config.json")).unwrap()).unwrap();
    let pin: [u8; 32] = data_encoding::HEXLOWER
        .decode(config.manifest_sha256.as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let read = |name: &str| std::fs::read(directory.join(name)).unwrap();
    let (manifest, circuit, keys, g1, g2) = (
        read("manifest.json"),
        read("circuits.json"),
        read("keys.json"),
        read("setup/g1.dat"),
        read("setup/g2.dat"),
    );
    let group = WaveArtifacts::authenticate(ArtifactBytes {
        manifest: &manifest,
        manifest_sha256: pin,
        circuit: &circuit,
        keys: &keys,
        srs_g1: &g1,
        srs_g2: &g2,
    })
    .unwrap();
    assert_eq!(group.issuer_key().to_vec(), fixture.issuer_key);
    let proof = |case: &Case| {
        data_encoding::HEXLOWER
            .decode(case.proof.as_bytes())
            .unwrap()
    };
    let wave = fixture.cases.iter().find(|c| c.kind == "wave").unwrap();
    let outcome = fixture.cases.iter().find(|c| c.kind == "outcome").unwrap();
    let statement = |case: &Case| case.statement["wave"].clone();
    let reservation: WaveStatement = serde_json::from_value(statement(wave)).unwrap();
    let settled: WaveOutcomeStatement =
        serde_json::from_value(outcome.statement["outcome"].clone()).unwrap();
    let policy: ExtensionPolicy = serde_json::from_value(wave.statement["policy"].clone()).unwrap();
    let c = &reservation.context;
    let wave_policy = WavePolicy {
        community: c.community,
        extension: policy,
        proof_scope: ProofScope {
            circuit_digest: fixture.extension_scope.circuit_digest,
            verifying_key_digest: fixture.extension_scope.verifying_key_digest,
        },
        certificate_key: fixture.issuer_key.clone(),
        manifest_sha256: group.manifest_sha256(),
        state_policy: reservation.state_policy,
        valid_from: 1,
        valid_until: c.expires_at + 1000,
    };
    let now = settled.evidence.accepted_at.max(reservation.accepted_at) + 1;
    let options = common::native::options(1024 * 1024);
    let verifier = WaveVerifier::native(
        wave_policy,
        now,
        c.expires_at + 1000,
        group.wave_config(options.clone()),
        group.outcome_config(options),
    )
    .unwrap();
    Loaded {
        verifier,
        reservation: (reservation, proof(wave)),
        outcome: (settled, proof(outcome)),
        now,
    }
}

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
