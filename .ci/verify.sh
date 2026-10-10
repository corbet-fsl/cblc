#!/usr/bin/env bash
# .ci/verify.sh for corbet-libs/cblc — ports ALL Linux verification gates from
# .github/workflows/ci.yml (jobs check, audit, dependency-policy, coverage) in full
# ordering, environment, and flags, except the advisory DB gate which lives in
# the separate fresh [checks.advisories] (`cargo deny check advisories licenses`).
set -euo pipefail
# Merge stderr into stdout so the captured Crow log shows gate diagnostics.
exec 2>&1
# Minimal accurate stage labels from the post-compile window onward; EXIT
# reports last gate + original status only (no dumps). Each label names the
# gate the NEXT command belongs to, so a later failure is never attributed
# to a stale earlier label. Earlier stages keep init.
CBLC_LAST_GATE="init"
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "CBLC-DIAG last_gate=$CBLC_LAST_GATE exit=$rc"; fi; exit "$rc"' EXIT
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
export CBLC_PROOF_DIRECTORY="${CBLC_PROOF_DIRECTORY:-$PWD/.proof-test}"
export CBLC_LEDGER_FIXTURES="${CBLC_LEDGER_FIXTURES:-1}"

# --- check job (stable) ---
# Node major must match source CI (node-version 24); fail clearly otherwise.
node --version | grep -q '^v24\.' || { echo 'CI requires Node major 24' >&2; exit 2; }
command -v jq >/dev/null || { echo 'missing jq' >&2; exit 2; }
command -v wasm-pack >/dev/null || { echo 'missing wasm-pack' >&2; exit 2; }
# Wasm target on stable is guaranteed by run-cached.sh (helper readiness +
# exclusive provisioning); no toolchain mutation here under the shared lock.
rustc --version
cargo fmt --check || { cargo fmt; git diff > formatting.patch; exit 1; }
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --test service_schema generated_projection_preserves_every_serde_constraint
npm ci --ignore-scripts --no-audit --no-fund
npm test
# CI caches .proof-test across runs (key proofs-v1-<os>-<hash of
# experiments/private-accounting/account-state/**, runtime/accounting/**,
# tests/real-proof.mjs, tests/holder/**, package*.json>); verify builds it
# fresh every run.
mkdir -p "$CBLC_PROOF_DIRECTORY"
node tests/real-proof.mjs
cargo test --locked --all-features --no-fail-fast -- --test-threads=2
# CI caches .extension-test across runs (key extension-public-v1-<os>-<hash of
# circuits/extensions/**, runtime/extensions/**, tests/extensions-proof.mjs,
# tests/holder/extension-checkpoint.mjs, tests/common/mod.rs,
# examples/extension_issuer.rs, package*.json>); verify runs the cache-miss
# path fresh, then also replays the fixtures against the current issuer (the
# cache-hit path both keeps validating the same fixtures).
node runtime/extensions/compile.mjs
CBLC_LAST_GATE="wasm-pack-build"
wasm-pack build node_modules/@corbet-labs/cwlt --target web --release --out-dir "$PWD/.extension-wasm"
CBLC_LAST_GATE="issuer-build"
cargo build --locked --example extension_issuer
mkdir -p .extension-test
git rev-parse HEAD > .extension-test/source.txt
sha256sum package-lock.json >> .extension-test/source.txt
CBLC_LAST_GATE="proof"
# The ci-job exports a persistent CARGO_TARGET_DIR (absolute); resolve it once
# so the proof and replay use the actual `cargo build` output dir. Gate unchanged.
cblc_target_dir="${CARGO_TARGET_DIR:-target}"
case "$cblc_target_dir" in
  /*) cblc_issuer="$cblc_target_dir/debug/examples/extension_issuer" ;;
  *) cblc_issuer="$PWD/$cblc_target_dir/debug/examples/extension_issuer" ;;
esac
CBLC_EXTENSION_ISSUER="$cblc_issuer" node tests/extensions-proof.mjs
CBLC_LAST_GATE="replay"
CBLC_EXTENSION_ISSUER="$cblc_issuer" node tests/replay-extensions.mjs
CBLC_LAST_GATE="adversaries"
cargo run --locked --all-features --example extension_adversaries

# --- audit job, deterministic part only (stable; CI needs: resolve, check) ---
# The advisory DB gate (`cargo deny check advisories licenses`) is NOT run
# here; it lives in the separate fresh [checks.advisories] so the RustSec DB
# is always re-queried and never restored from cache.
CBLC_LAST_GATE="audit-metadata"
cargo metadata --locked --format-version 1 > dependency-metadata.json
node .github/check-advisory-exposure.mjs

# --- dependency-policy job (stable; CI needs: resolve) ---
CBLC_LAST_GATE="dependency-policy"
python3 .github/check-first-party.py

# --- coverage job (nightly only; CI needs: resolve, check; reuses the
# .proof-test and .extension-test produced above in place of CI's
# proof-fixtures and extension-public-proofs artifacts) ---
npm ci --ignore-scripts --no-audit --no-fund
# Select nightly exactly as CI's nightly job does; every bare cargo/rustc
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
export CARGO_TARGET_DIR="$coverage_target"
source <("$NIGHTLY_CARGO" llvm-cov show-env --sh --branch --no-cfg-coverage --no-cfg-coverage-nightly)
"$NIGHTLY_CARGO" llvm-cov clean --workspace
CBLC_LAST_GATE="nightly-tests"
"$NIGHTLY_CARGO" test --locked --workspace --all-features -- --test-threads=2
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
# The environment above remains active in this shell. Unlike separate GitHub
# Actions steps, reports must not source show-env again: cargo-llvm-cov can
# record its own compiler wrapper as the predecessor and recursively invoke it.
# Only report/clean are supported inside the environment produced by show-env.
# Retain raw coverage even when a real execution fails (CI: if always()).
CBLC_LAST_GATE="coverage-report"
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/|/examples/' --json --output-path coverage.json
# Retain source coverage diagnostics from the same execution (CI: if always()).
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/|/examples/' --lcov --output-path coverage.lcov
# Retain independent annotated source inventory (CI: if always()).
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/|/examples/' --text --output-path coverage.txt
)
# Require complete source line and branch coverage.
CBLC_LAST_GATE="coverage-check"
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
