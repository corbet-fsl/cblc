#!/usr/bin/env bash
# Nightly source and runtime coverage over real native round trips. Restores the
# fixtures retained by proof-scenario and record-epoch for this commit.
: "${CI_COMMIT_SHA:?Missing verified source revision}"
source "$(dirname "${BASH_SOURCE[0]}")/job-env.sh"
npm ci --ignore-scripts --no-audit --no-fund
# V8 instrumentation measures legacy SDK fixture helpers only.
# Authoritative backend coverage comes from the native Rust adapters below.
test ! -e .runtime-v8 || { echo 'Stale runtime coverage directory' >&2; exit 2; }
mkdir .runtime-v8
export NODE_V8_COVERAGE="$PWD/.runtime-v8"
npm test
test "$CBLC_PROOF_DIRECTORY" = "$PWD/.proof-test" || { echo 'Fixture restore requires the job-local directory' >&2; exit 2; }
CBLC_LAST_GATE="restore"
restore_fixture proof-scenario
restore_fixture record-epoch
CBLC_LAST_GATE="wasm-pack-build"
env -u RUSTFLAGS wasm-pack build node_modules/@corbet-labs/cwlt --target web --release --out-dir "$PWD/.extension-wasm"
# Select nightly explicitly; every bare cargo/rustc
# below resolves nightly via RUSTC/CARGO/PATH/RUSTUP_TOOLCHAIN.
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Measure real native round trips and failure paths.
set -euo pipefail
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
# cargo refuses to clean a target directory without the standard cache tag.
printf 'Signature: 8a477f597d28d172789f06886806bc55\n' > "$coverage_target/CACHEDIR.TAG"
export CARGO_TARGET_DIR="$coverage_target"
source <("$NIGHTLY_CARGO" llvm-cov show-env --sh --branch --no-cfg-coverage --no-cfg-coverage-nightly)
"$NIGHTLY_CARGO" llvm-cov clean --workspace
CBLC_LAST_GATE="nightly-tests"
"$NIGHTLY_CARGO" build --locked --example czkp_bb_worker
export CBLC_BB="$CARGO_TARGET_DIR/debug/examples/czkp_bb_worker"
test -x "$CBLC_BB"
"$NIGHTLY_CARGO" test --locked --workspace --all-features -- --test-threads=2 --skip the_retained_reservation_and_answer
node .ci/replay-account-proofs.ts
CBLC_LAST_GATE="instrumented-build"
"$NIGHTLY_CARGO" build --locked --all-features --example extension_issuer --example extension_adversaries --message-format=json > instrumented-build.json
CBLC_EXTENSION_ISSUER="$(jq -ers 'map(select(.reason == "compiler-artifact" and .target.name == "extension_issuer" and .executable != null)) | if length == 1 then .[0].executable else error("Expected exactly one issuer executable") end' instrumented-build.json)"
export CBLC_EXTENSION_ISSUER
test -x "$CBLC_EXTENSION_ISSUER"
CBLC_LAST_GATE="nightly-replay"
node tests/replay-extensions.mjs
adversaries="$(jq -ers 'map(select(.reason == "compiler-artifact" and .target.name == "extension_adversaries" and .executable != null)) | if length == 1 then .[0].executable else error("Expected exactly one adversary executable") end' instrumented-build.json)"
CBLC_LAST_GATE="nightly-adversaries"
"$adversaries"
# The environment above remains active in this shell. Reports must not source
# show-env again: cargo-llvm-cov can
# record its own compiler wrapper as the predecessor and recursively invoke it.
# Only report/clean are supported inside the environment produced by show-env.
# Export completed execution evidence; the outer EXIT hook retains completed
# reports even when a later report or coverage gate fails.
CBLC_LAST_GATE="coverage-report"
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/|/examples/' --json --output-path coverage.json
# Retain source coverage diagnostics from the same completed execution.
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/|/examples/' --lcov --output-path coverage.lcov
# Retain independent annotated source inventory from that execution.
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/|/examples/' --text --output-path coverage.txt
)
# Require complete source line and branch coverage.
CBLC_LAST_GATE="coverage-check"
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt

CBLC_LAST_GATE="runtime-coverage-report"
unset NODE_V8_COVERAGE
runtime_coverage_status=0
npm run coverage:runtime:report || runtime_coverage_status=$?
tar -czf runtime-coverage/v8.json.tar.gz -C .runtime-v8 .
exit "$runtime_coverage_status"
