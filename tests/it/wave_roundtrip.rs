//! Counterpart verification of the retained real wave and Answer proofs through
//! cwlt's `WaveVerifier` and the native worker: the proofs were produced by the
//! `proof-fixtures` job and are addressed by their digest.
#![allow(dead_code)]
#![cfg(feature = "publication")]
use cblc::artifacts::{ArtifactBytes, WaveArtifacts};
use cwlt::wave::{
    ExtensionPolicy, VerifiedWaveOutcome, WaveContext, WaveOutcome, WaveOutcomeStatement,
    WavePolicy, WaveStatement, WaveVerifier,
};
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
    /// The published verifier material of the issuer that produced the proofs (`material` op).
    material: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    manifest_sha256: String,
}

struct Loaded {
    group: WaveArtifacts,
    /// The Wave policy exactly as the published material derives it.
    policy: WavePolicy,
    /// The published verifier material the policy was derived from.
    material: serde_json::Value,
    until: u64,
    verifier: WaveVerifier<cvfy::NativeVerifier>,
    reservation: (WaveStatement, Vec<u8>),
    outcome: (WaveOutcomeStatement, Vec<u8>),
    now: u64,
}

fn build(
    group: &WaveArtifacts,
    policy: WavePolicy,
    now: u64,
    until: u64,
) -> Result<WaveVerifier<cvfy::NativeVerifier>, czkp::Error> {
    let options = crate::common::native::options(1024 * 1024);
    WaveVerifier::native(
        policy,
        now,
        until,
        group.wave_config(options.clone()),
        group.outcome_config(options),
    )
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
    // The policy comes from the published material the issuer generated, never from the
    // statement being verified; the statement must agree with it, not define it.
    let wave_policy: WavePolicy =
        serde_json::from_value(fixture.material["waveVerifier"].clone()).unwrap();
    assert_eq!(wave_policy.community, c.community);
    assert_eq!(wave_policy.extension, policy);
    assert_eq!(wave_policy.state_policy, reservation.state_policy);
    // The published ring holds the key the fixture certificates were signed with, open at
    // their acceptance time.
    assert_eq!(
        czkp::issuer_keys::key_at(&wave_policy.certificate_keys, reservation.accepted_at)
            .unwrap()
            .to_vec(),
        fixture.issuer_key
    );
    assert_eq!(
        wave_policy.proof_scope.circuit_digest,
        fixture.extension_scope.circuit_digest
    );
    assert_eq!(
        wave_policy.proof_scope.verifying_key_digest,
        fixture.extension_scope.verifying_key_digest
    );
    let now = settled.evidence.accepted_at.max(reservation.accepted_at) + 1;
    let until = c.expires_at + 1000;
    let verifier = build(&group, wave_policy.clone(), now, until).unwrap();
    Loaded {
        group,
        policy: wave_policy,
        material: fixture.material.clone(),
        until,
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

#[test]
fn a_policy_that_differs_from_the_published_material_refuses_the_proofs() {
    let l = load();
    let (statement, proof) = &l.reservation;
    let expected: WaveContext = statement.context.clone();
    let refused = |policy: WavePolicy| match build(&l.group, policy, l.now, l.until) {
        Err(_) => true,
        Ok(v) => block_on(v.verify(statement, proof, &expected, l.now)).is_err(),
    };
    assert!(!refused(l.policy.clone()));
    let mut flipped = l.policy.clone();
    flipped.community[0] ^= 1;
    assert!(refused(flipped));
    let mut flipped = l.policy.clone();
    flipped.state_policy[0] ^= 1;
    assert!(refused(flipped));
    let mut flipped = l.policy.clone();
    flipped.proof_scope.circuit_digest[0] ^= 1;
    assert!(refused(flipped));
    // The account verifying-key digest is no Wave authority (the accepted-state certificate
    // binds the account circuit digest; the Wave keys are pinned by the authenticated group).
    // The published material owns it: a descriptor whose digest differs from the material's
    // derivation is refused there, and Wave proofs checked under another relation's key fail.
    let material: cblc::publication::PublicVerifierMaterial =
        serde_json::from_value(l.material.clone()).unwrap();
    material.validate(&material.community).unwrap();
    let mut forged = material.clone();
    forged
        .wave_verifier
        .as_mut()
        .unwrap()
        .proof_scope
        .verifying_key_digest[0] ^= 1;
    assert!(forged.validate(&forged.community).is_err());
    let options = crate::common::native::options(1024 * 1024);
    let swapped = WaveVerifier::native(
        l.policy.clone(),
        l.now,
        l.until,
        l.group.outcome_config(options.clone()),
        l.group.wave_config(options),
    )
    .unwrap();
    assert!(block_on(swapped.verify(statement, proof, &expected, l.now)).is_err());
    // Another community identity, or a ring whose signing key retired before the
    // certificate's acceptance time, refuses the same proof.
    let mut flipped = l.policy.clone();
    flipped.community_identity[0] ^= 1;
    assert!(refused(flipped));
    let mut retired = l.policy.clone();
    let open = retired.certificate_keys.last_mut().unwrap();
    open.valid_from = 1;
    open.valid_until = Some(statement.accepted_at);
    let successor = cssr::certificate::CertificateIssuer::new(&[4; 32]).unwrap();
    retired
        .certificate_keys
        .push(czkp::issuer_keys::CertificateKeyPeriod {
            public_key: successor.public_key().to_vec(),
            valid_from: statement.accepted_at,
            valid_until: None,
        });
    assert!(refused(retired));
}
