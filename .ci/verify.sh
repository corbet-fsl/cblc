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
python3 -B .ci/test-proof-cache.py
python3 -B .ci/test-native-sdk.py
python3 -B .ci/check-native-sdk.py
# Wasm target on stable is guaranteed by run-cached.sh (helper readiness +
# exclusive provisioning); no toolchain mutation here under the shared lock.
rustc --version
cargo fmt --check || { cargo fmt; git diff > formatting.patch; exit 1; }
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --example czkp_bb_worker
cblc_target_dir="${CARGO_TARGET_DIR:-target}"
export CBLC_BB="$(realpath "$cblc_target_dir/debug/examples/czkp_bb_worker")"
test -x "$CBLC_BB"
cargo test --locked --all-features --test service_schema generated_projection_preserves_every_serde_constraint
npm ci --ignore-scripts --no-audit --no-fund
# V8 instrumentation measures legacy SDK fixture helpers only.
# Authoritative backend coverage comes from the native Rust adapters below.
test ! -e .runtime-v8 || { echo 'Stale runtime coverage directory' >&2; exit 2; }
mkdir .runtime-v8
export NODE_V8_COVERAGE="$PWD/.runtime-v8"
npm test
# As in source CI, reuse only complete fictional public proof fixtures. The
# stronger local key also binds all Rust code/locks and this cache machinery.
# Cache entries contain no verification verdict: every current replay remains.
test "$CBLC_PROOF_DIRECTORY" = "$PWD/.proof-test" || { echo 'Proof cache requires the job-local fixture directory' >&2; exit 2; }
proof_fixture_cache="$ARTIFACT_ROOT/proof-fixtures-v1"
proof_fixture_evidence="$(mktemp)"
printf 'generation_commit=%s\n' "$CI_COMMIT_SHA" > "$proof_fixture_evidence"
proof_cache_hit=false
if python3 .ci/proof-cache.py restore --cache "$proof_fixture_cache"; then
  proof_cache_hit=true
else
  proof_cache_status=$?
  test "$proof_cache_status" -eq 3 || exit "$proof_cache_status"
fi
if ! "$proof_cache_hit"; then
  mkdir -p "$CBLC_PROOF_DIRECTORY"
  node tests/real-proof.mjs | tee -a "$proof_fixture_evidence"
fi
cargo test --locked --all-features --no-fail-fast -- --test-threads=2 | tee -a "$proof_fixture_evidence"
# Compilation is cheap compared with proof generation and remains measured on
# cache hits. Never overwrite the pinned circuits inside a restored fixture.
(
  export CBLC_EXTENSION_DIRECTORY="$PWD/.extension-test"
  if "$proof_cache_hit"; then
    compile_directory="$(mktemp -d)"
    trap 'rm -rf -- "$compile_directory"' EXIT
    export CBLC_EXTENSION_DIRECTORY="$compile_directory"
  fi
  node runtime/extensions/compile.mjs
)
CBLC_LAST_GATE="wasm-pack-build"
wasm-pack build node_modules/@corbet-labs/cwlt --target web --release --out-dir "$PWD/.extension-wasm"
CBLC_LAST_GATE="issuer-build"
cargo build --locked --example extension_issuer
mkdir -p .extension-test
CBLC_LAST_GATE="proof"
# The ci-job exports a persistent CARGO_TARGET_DIR (absolute); resolve it once
# so the proof and replay use the actual `cargo build` output dir. Gate unchanged.
cblc_target_dir="${CARGO_TARGET_DIR:-target}"
case "$cblc_target_dir" in
  /*) cblc_issuer="$cblc_target_dir/debug/examples/extension_issuer" ;;
  *) cblc_issuer="$PWD/$cblc_target_dir/debug/examples/extension_issuer" ;;
esac
if ! "$proof_cache_hit"; then
  git rev-parse HEAD > .extension-test/source.txt
  sha256sum package-lock.json >> .extension-test/source.txt
  CBLC_EXTENSION_ISSUER="$cblc_issuer" node tests/extensions-proof.mjs | tee -a "$proof_fixture_evidence"
fi
CBLC_LAST_GATE="replay"
node .ci/replay-account-proofs.ts
CBLC_EXTENSION_ISSUER="$cblc_issuer" node tests/replay-extensions.mjs | tee -a "$proof_fixture_evidence"
CBLC_LAST_GATE="adversaries"
cargo run --locked --all-features --example extension_adversaries | tee -a "$proof_fixture_evidence"
if ! "$proof_cache_hit"; then
  python3 .ci/proof-cache.py publish --cache "$proof_fixture_cache" --evidence "$proof_fixture_evidence" --generation-commit "$CI_COMMIT_SHA"
fi

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
"$NIGHTLY_CARGO" build --locked --example czkp_bb_worker
export CBLC_BB="$CARGO_TARGET_DIR/debug/examples/czkp_bb_worker"
test -x "$CBLC_BB"
"$NIGHTLY_CARGO" test --locked --workspace --all-features -- --test-threads=2
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

CBLC_LAST_GATE="runtime-coverage-report"
unset NODE_V8_COVERAGE
runtime_coverage_status=0
npm run coverage:runtime:report || runtime_coverage_status=$?
tar -czf runtime-coverage/v8.json.tar.gz -C .runtime-v8 .
exit "$runtime_coverage_status"
