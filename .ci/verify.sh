#!/usr/bin/env bash
# Static gates, native integration tests, replays and dependency audit. The real
# proof fixtures come from the proof-scenario and record-epoch jobs (retained
# write-once under this commit); the nightly coverage run is the coverage job.
# The advisory DB gate lives in the separate fresh [checks.advisories]
# (`cargo deny check advisories licenses`).
: "${CI_COMMIT_SHA:?Missing verified source revision}"
source "$(dirname "${BASH_SOURCE[0]}")/job-env.sh"
python3 -B .ci/test-proof-cache.py
python3 -B .ci/test-native-sdk.py
python3 -B .ci/check-native-sdk.py
rustc --version
cargo fmt --check || { cargo fmt; git diff > formatting.patch; exit 1; }
cargo clippy --locked --all-targets --all-features -- -D warnings
# The portable account contracts must build and keep their wire without `host`.
cargo test --locked --no-default-features --test contracts
cargo test --locked --no-default-features --features schema --test contracts
python3 -B .ci/test-commit-deadline-output.py
python3 -B .ci/test-commit-deadline-regression.py
python3 -B .ci/test-retain-record-fixture.py
cargo test --locked --all-features --lib
cargo test --locked --all-features --test service_schema generated_projection_preserves_every_serde_constraint
npm ci --ignore-scripts --no-audit --no-fund
node .ci/check-fixture-suite.ts
# Fixtures retained by proof-scenario and record-epoch on this commit.
CBLC_LAST_GATE="restore"
test "$CBLC_PROOF_DIRECTORY" = "$PWD/.proof-test" || { echo 'Fixture restore requires the job-local directory' >&2; exit 2; }
restore_fixture proof-scenario
restore_fixture record-epoch
CBLC_LAST_GATE="wasm-pack-build"
env -u RUSTFLAGS wasm-pack build node_modules/@corbet-labs/cwlt --target web --release --out-dir "$PWD/.extension-wasm"
CBLC_LAST_GATE="issuer-build"
cargo build --locked --example extension_issuer --features publication
build_bb_worker
cblc_issuer="$(issuer_path)"
CBLC_LAST_GATE="native-tests"
# The retained wave proof test needs the wave fixture and runs in the wave-verify job.
cargo test --locked --all-features --no-fail-fast -- --test-threads=2 --skip the_retained_reservation_and_answer
CBLC_LAST_GATE="replay"
node .ci/replay-account-proofs.ts
CBLC_EXTENSION_ISSUER="$cblc_issuer" node tests/replay-extensions.mjs
CBLC_LAST_GATE="adversaries"
cargo run --locked --all-features --example extension_adversaries
python3 -B .ci/test-extension-scope-output.py
python3 -B .ci/test-extension-scope-regression.py

# --- deterministic audit over the committed dependency resolution ---
CBLC_LAST_GATE="audit-metadata"
cargo metadata --locked --format-version 1 > dependency-metadata.json
node .github/check-advisory-exposure.mjs
CBLC_LAST_GATE="dependency-policy"
python3 .github/check-first-party.py
