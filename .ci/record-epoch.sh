#!/usr/bin/env bash
# The record-epoch relation: real proofs, the native record capture (retained under
# its own digest for artifact-conformance) and the .record-epoch-test fixture
# (retained write-once for verify and coverage). Needs the proof-scenario fixtures.
: "${CI_COMMIT_SHA:?Missing verified source revision}"
source "$(dirname "${BASH_SOURCE[0]}")/job-env.sh"
python3 -B .ci/check-native-sdk.py
npm ci --ignore-scripts --no-audit --no-fund
build_bb_worker
# The record scenario reuses the account fixtures of this commit (run proof-scenario first).
restore_fixture proof-scenario
python3 -B .ci/record-worker.py export --worker "$CBLC_BB" --output "$ARTIFACT_ROOT/gather-record-fixture"
CBLC_LAST_GATE="wasm-pack-build"
env -u RUSTFLAGS wasm-pack build node_modules/@corbet-labs/cwlt --target web --release --out-dir "$PWD/.extension-wasm"
CBLC_LAST_GATE="issuer-build"
cargo build --locked --example extension_issuer --features publication
cblc_issuer="$(issuer_path)"
test ! -e .record-epoch-test || { echo 'Existing fixture output refuses overwrite' >&2; exit 2; }
CBLC_LAST_GATE="proof"
(
  export CBLC_EXTENSION_DIRECTORY="$PWD/.record-epoch-test"
  node runtime/extensions/compile.mts --record-epoch
  CBLC_EXTENSION_ISSUER="$cblc_issuer" node tests/extensions-proof.mts --record-epoch-proofs
)
# Keep this genuine capture once under its own digest; consumers pin that digest.
python3 -B .ci/retain-record-fixture.py
CBLC_LAST_GATE="retain"
retain_fixture record-epoch .record-epoch-test
