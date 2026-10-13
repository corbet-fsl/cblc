#!/usr/bin/env bash
# Real account proofs and the extension proof scenario; retains .proof-test and
# .extension-test write-once for verify and coverage.
: "${CI_COMMIT_SHA:?Missing verified source revision}"
source "$(dirname "${BASH_SOURCE[0]}")/job-env.sh"
python3 -B .ci/check-native-sdk.py
npm ci --ignore-scripts --no-audit --no-fund
build_bb_worker
test ! -e .proof-test && test ! -e .extension-test || { echo 'Existing fixture output refuses overwrite' >&2; exit 2; }
mkdir -p "$CBLC_PROOF_DIRECTORY"
CBLC_LAST_GATE="real-proof"
node tests/real-proof.mjs
(
  export CBLC_EXTENSION_DIRECTORY="$PWD/.extension-test"
  node runtime/extensions/compile.mts
)
CBLC_LAST_GATE="wasm-pack-build"
env -u RUSTFLAGS wasm-pack build node_modules/@corbet-labs/cwlt --target web --release --out-dir "$PWD/.extension-wasm"
CBLC_LAST_GATE="issuer-build"
cargo build --locked --example extension_issuer --features publication
mkdir -p .extension-test
cblc_issuer="$(issuer_path)"
CBLC_LAST_GATE="proof"
git rev-parse HEAD > .extension-test/source.txt
sha256sum package-lock.json >> .extension-test/source.txt
CBLC_EXTENSION_ISSUER="$cblc_issuer" node tests/extensions-proof.mts
CBLC_LAST_GATE="adversaries"
cargo run --locked --all-features --example extension_adversaries
cp .extension-test/publication.json "$ARTIFACT_ROOT/balance-publication.json"
CBLC_LAST_GATE="retain"
retain_fixture proof-scenario .proof-test .extension-test
