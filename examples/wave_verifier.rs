//! CI counterpart verifier. Separate from the issuer fixture: peer identities
//! and presentations are never sent to a named account service.
use cwlt::wave::{
    WaveContext, WaveOutcome, WaveOutcomeStatement, WavePolicy, WaveStatement, WaveVerifier,
};
use std::{
    io::{self, BufRead},
    path::PathBuf,
    time::Duration,
};
fn main() {
    let config_path = PathBuf::from(std::env::args().nth(1).unwrap());
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::args().nth(2).unwrap()).unwrap()).unwrap();
    let ring = csgn::KeyRing::from_cbor(
        &serde_json::from_value::<Vec<u8>>(fixture["configuredFixtureRing"].clone()).unwrap(),
    )
    .unwrap();
    let signed: Vec<u8> = serde_json::from_value(fixture["signed"].clone()).unwrap();
    let balance = cbcn::balance::Balance::verify(&ring, &signed, 1, 1, 100).unwrap();
    let policy = WavePolicy::from_balance(&balance, 100).unwrap();
    let config = czkp::process::ProcessVerifierConfig {
        node: std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("node"))
            .find(|p| p.is_absolute() && p.is_file())
            .unwrap(),
        script: PathBuf::from(std::env::args().nth(3).unwrap()),
        artifact_config: config_path,
        scope: policy.proof_scope.clone(),
        timeout: Duration::from_secs(180),
        maximum_parallel: 1,
        max_proof_bytes: 1024 * 1024,
        node_heap_megabytes: 4096,
    };
    let verifier = WaveVerifier::from_balance(&balance, config, 100).unwrap();
    for line in io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let expected: WaveContext = serde_json::from_value(request["expected"].clone()).unwrap();
        let proof = data_encoding::HEXLOWER
            .decode(request["proof"].as_str().unwrap().as_bytes())
            .unwrap();
        let now = request["now"].as_u64().unwrap();
        let result = if let Some(outcome) = request.get("expectedOutcome") {
            let statement: WaveOutcomeStatement =
                serde_json::from_value(request["statement"].clone()).unwrap();
            let outcome: WaveOutcome = serde_json::from_value(outcome.clone()).unwrap();
            let digest: [u8; 32] =
                serde_json::from_value(request["expectedReceiptDigest"].clone()).unwrap();
            let result = verifier
                .verify_outcome_detailed(&statement, &proof, &expected, outcome, &digest, now);
            if let Ok(value) = &result {
                assert_eq!(value.context(), &expected);
                assert_eq!(value.outcome(), outcome);
                assert_eq!(value.receipt_digest(), &digest);
            }
            result.map(|_| ())
        } else {
            let statement: WaveStatement =
                serde_json::from_value(request["statement"].clone()).unwrap();
            let result = verifier.verify_detailed(&statement, &proof, &expected, now);
            if let Ok(value) = &result {
                assert_eq!(value.context(), &expected);
            }
            result.map(|_| ())
        };
        // The full fixture retains this public reply for the exact attempt.
        // Never attach request bytes, stderr, OS messages or executable paths.
        let diagnostic = result.as_ref().err().map(|failure| failure.category());
        if let Err(failure) = &result {
            eprintln!("CI public Wave refusal: {}", failure.category());
        }
        println!(
            "{}",
            serde_json::json!({"verified":result.is_ok(),"diagnostic":diagnostic})
        );
    }
}
