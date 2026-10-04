#!/usr/bin/env bash
# Diagnostic composition of explicit candidates; never ordinary main qualification.
set -euo pipefail
fixture=record-diagnostic
if [[ $# == 1 && $1 == --full-extension ]]; then
    fixture=full-extension
elif [[ $# != 0 ]]; then
    printf '%s\n' 'Unknown proof fixture selector' >&2
    exit 2
fi
: "${CI:?CI only}" "${CARGO_HOME:?}" "${CI_COMMIT_SHA:?}" "${SOURCE_SHA256:?}" "${CI_REPOSITORY_URL:?}"
: "${DEPENDENCY_CLOSURE_MANIFEST:?verified original closure required}" "${DEPENDENCY_CLOSURE_SHA256:?}"
: "${G2_WASM_PACK_BINARY:?}" "${G2_WASM_PACK_SHA256:?}"
[[ "${CI_JOBS:?}" =~ ^[12]$ ]] && [[ "${CI_TEST_THREADS:?}" =~ ^[12]$ ]]
[[ "${CI_MEMORY_MB:?}" =~ ^[1-9][0-9]{0,4}$ ]] && ((CI_MEMORY_MB <= 16384))
export UV_THREADPOOL_SIZE=2 RAYON_NUM_THREADS=2 OMP_NUM_THREADS=2
mkdir -p "$CARGO_HOME/ccid-artifacts/cblc-g2-proof-diagnostic"
report_dir=$(mktemp -d "$CARGO_HOME/ccid-artifacts/cblc-g2-proof-diagnostic/$CI_COMMIT_SHA.XXXXXXXX")
export CBLC_DIAGNOSTIC_OUTPUT="$report_dir" CI_ACCEPTANCE_ARTIFACTS="$report_dir"
wallet_dir="$(pwd -P)/experiments/private-accounting/node_modules/@corbet-labs/cwlt"
finish() {
    code=$?
    if [[ -f Cargo.lock ]]; then cp Cargo.lock "$report_dir/final-Cargo.lock"; fi
    if [[ -f "$wallet_dir/Cargo.lock" ]]; then
        cp "$wallet_dir/Cargo.lock" "$report_dir/final-cwlt-Cargo.lock"
    fi
    python3 - "$report_dir" "$code" "$fixture" <<'PY'
import hashlib, json, os, pathlib, sys
root, code = pathlib.Path(sys.argv[1]), int(sys.argv[2])
fixture = sys.argv[3]
files = {}
for path in root.rglob('*'):
    if path.is_file():
        with path.open('rb') as stream:
            files[str(path.relative_to(root))] = hashlib.file_digest(stream, 'sha256').hexdigest()
scope = 'g2-full-extension-proof-diagnostic' if fixture == 'full-extension' else 'g2-record-proof-diagnostic'
receipt = {'schema': 1, 'scope': scope,
           'extension_fixture': fixture,
           'status': 'passed' if code == 0 else 'failed', 'exit_code': code,
           'commit': os.environ['CI_COMMIT_SHA'], 'source_sha256': os.environ['SOURCE_SHA256'],
           'repository': os.environ['CI_REPOSITORY_URL'],
           'observed_main_closure_sha256': os.environ['DEPENDENCY_CLOSURE_SHA256'],
           'candidate_sources': 'candidate-sources.json',
           'candidate_patches': {name: f'candidate-patches-{name}.toml' for name in ['cblc', 'cwlt']},
           'artifacts': files, 'product_acceptance': False, 'full_suite': False,
           'browser_evidence': False, 'wasm_opt_postprocessing': False,
           'resolution_only_candidates': {
               name: {'compiled': False if code == 0 else None, 'qualified': False}
               for name in ['ckmg', 'cpsd']},
           'proof_round_trip_passed': code == 0}
(root / 'diagnostic.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps({'diagnostic_receipt': str(root / 'diagnostic.json'), 'status': receipt['status']}))
PY
    exit "$code"
}
trap finish EXIT
run() { "$@" 2>&1 | tee -a "$report_dir/check.log"; }
cp "$DEPENDENCY_CLOSURE_MANIFEST" "$report_dir/observed-main-closure.json"
cp Cargo.lock "$report_dir/baseline-Cargo.lock"
cp package-lock.json "$report_dir/baseline-package-lock.json"
cp experiments/private-accounting/package-lock.json "$report_dir/experiment-package-lock.json"
sha256sum experiments/private-accounting/package-lock.json > "$report_dir/npm-lock.sha256"
rustc --version --verbose > "$report_dir/rustc.txt"
cargo --version > "$report_dir/cargo.txt"
test -z "${RUSTC_BOOTSTRAP:-}"
python3 - "$report_dir/rustc.txt" <<'PY'
import pathlib, sys
compiler = pathlib.Path(sys.argv[1]).read_text()
if '-nightly' in compiler or '-beta' in compiler:
    raise SystemExit('Provisioned stable compiler required')
PY
wasm_libdir=$(rustc --print target-libdir --target wasm32-unknown-unknown)
compgen -G "$wasm_libdir/libstd-*.rlib" > "$report_dir/wasm-std.txt"
node --version > "$report_dir/node.txt"
npm --version > "$report_dir/npm.txt"
printf '%s  %s\n' "$G2_WASM_PACK_SHA256" "$G2_WASM_PACK_BINARY" | sha256sum --check --strict
"$G2_WASM_PACK_BINARY" --version > "$report_dir/wasm-pack.txt"
printf '%s  %s\n' "$G2_WASM_PACK_SHA256" "$G2_WASM_PACK_BINARY" > "$report_dir/wasm-pack.sha256"
run npm ci --prefix "$PWD/experiments/private-accounting" --workspaces=false --ignore-scripts --no-audit --no-fund
test ! -e node_modules
ln -s experiments/private-accounting/node_modules node_modules
# The maintained native binary is part of the integrity-checked npm package.
# Verify it can execute before any Rust build; never fall back to another backend.
export BB_BINARY_PATH="$PWD/node_modules/@aztec/bb.js/build/amd64-linux/bb"
test -x "$BB_BINARY_PATH"
"$BB_BINARY_PATH" --version > "$report_dir/bb-version.txt"
sha256sum "$BB_BINARY_PATH" > "$report_dir/bb.sha256"
node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {findBbBinary} from '@aztec/bb.js/platform';
const pkg=JSON.parse(await readFile('node_modules/@aztec/bb.js/package.json'));
assert.equal(pkg.version,'5.0.0');
assert.equal(findBbBinary(),process.env.BB_BINARY_PATH);
assert((await readFile(process.env.CBLC_DIAGNOSTIC_OUTPUT+'/bb-version.txt','utf8')).includes(pkg.version));
JS
run python3 .ci/g2-candidates.py unpack
cp "$wallet_dir/Cargo.lock" "$report_dir/baseline-cwlt-Cargo.lock"
# Each actual workspace resolves once. Both exact resulting graphs are retained.
run python3 .ci/g2-candidates.py select-patches cblc resolve
run cargo update
cp Cargo.lock "$report_dir/Cargo.lock"
sha256sum Cargo.lock > "$report_dir/cblc-resolved-lock.sha256"
date -u +%FT%TZ > "$report_dir/cblc-resolved-at.txt"
run python3 .ci/g2-candidates.py select-patches cwlt resolve
run cargo update --manifest-path "$wallet_dir/Cargo.toml"
sha256sum --check --strict "$report_dir/cblc-resolved-lock.sha256"
date -u +%FT%TZ > "$report_dir/resolved-at.txt"
cp "$wallet_dir/Cargo.lock" "$report_dir/cwlt-Cargo.lock"
sha256sum Cargo.lock "$wallet_dir/Cargo.lock" > "$report_dir/cargo-locks.sha256"
run python3 .ci/g2-candidates.py check-lock-patches
metadata() {
    local label=$1 locked_code probe_code
    shift
    run python3 .ci/g2-candidates.py select-patches "$label" metadata
    if cargo metadata --locked "$@" > "$report_dir/$label-metadata.json" \
        2> "$report_dir/$label-metadata.stderr"; then
        run python3 .ci/g2-candidates.py record-metadata-patches "$label"
        return 0
    else
        locked_code=$?
    fi
    cat "$report_dir/$label-metadata.stderr" >&2
    # Refusal evidence only: a successful offline probe never permits a build.
    # Preserve both resolved locks and restore their exact bytes after inspection.
    if CARGO_LOG=cargo::ops::resolve=trace,cargo::ops::lockfile=trace,cargo::core::resolver=trace \
        timeout --kill-after=5s 30s cargo metadata --offline "$@" \
        > "$report_dir/$label-refusal-probe-metadata.json" \
        2> "$report_dir/$label-refusal-probe.stderr"; then
        probe_code=0
    else
        probe_code=$?
    fi
    python3 .ci/g2-lock-refusal.py "$label" "$locked_code" "$probe_code" || \
        printf '%s\n' 'Lock refusal evidence collection failed' >&2
    exit "$locked_code"
}
metadata cblc --all-features --format-version 1
metadata cwlt --manifest-path "$wallet_dir/Cargo.toml" --format-version 1
run python3 .ci/g2-candidates.py select-patches cblc check
run python3 .ci/g2-candidates.py check
# Original matched upstream CLI acquisition, scoped to this job's artifact path.
run bash .ci/g2-wasm-runner.sh
export PATH="$report_dir/runner:$PATH"
export WASM_PACK_CACHE="$PWD/.g2-wasm-pack-cache"
mkdir "$WASM_PACK_CACHE"
run python3 .ci/g2-candidates.py select-patches cblc fmt
run cargo fmt --all -- --check
run python3 .ci/g2-candidates.py select-patches cblc issuer
examples=(--example extension_issuer)
if [[ $fixture == full-extension ]]; then examples+=(--example wave_verifier); fi
cargo build --locked --all-features "${examples[@]}" --message-format=json > "$report_dir/issuer-build.json"
run python3 .ci/g2-candidates.py check-issuer-build
example_executable() {
python3 - "$report_dir/issuer-build.json" "$report_dir/cblc-metadata.json" "$1" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
root = json.load(open(sys.argv[2]))['resolve']['root']
executables = [r['executable'] for r in rows if r.get('reason') == 'compiler-artifact'
               and r.get('package_id') == root and r.get('target', {}).get('kind') == ['example']
               and r.get('target', {}).get('name') == sys.argv[3] and r.get('executable')]
if len(executables) != 1:
    raise SystemExit('Expected one current example executable: ' + sys.argv[3])
print(executables[0])
PY
}
CBLC_EXTENSION_ISSUER=$(example_executable extension_issuer)
export CBLC_EXTENSION_ISSUER
test -x "$CBLC_EXTENSION_ISSUER"
sha256sum "$CBLC_EXTENSION_ISSUER" > "$report_dir/issuer-executable.sha256"
if [[ $fixture == full-extension ]]; then
    CBLC_WAVE_VERIFIER=$(example_executable wave_verifier)
    export CBLC_WAVE_VERIFIER
    test -x "$CBLC_WAVE_VERIFIER"
    sha256sum "$CBLC_WAVE_VERIFIER" > "$report_dir/wave-verifier-executable.sha256"
    # The unchanged fixture uses this original relative path. Only link the
    # verified current compiler artifact into the fresh job-owned source tree.
    test ! -e target && test ! -L target
    mkdir -p target/debug/examples
    ln -s "$CBLC_WAVE_VERIFIER" target/debug/examples/wave_verifier
    python3 - "$report_dir" "$CBLC_WAVE_VERIFIER" <<'PY'
import hashlib, json, pathlib, sys
report, executable = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
alias = pathlib.Path.cwd() / 'target/debug/examples/wave_verifier'
if not executable.is_absolute() or not alias.is_symlink() or alias.resolve(strict=True) != executable.resolve(strict=True):
    raise SystemExit('Wave verifier alias does not identify the current compiler artifact')
def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
(report / 'wave-verifier-binding.json').write_text(json.dumps({
    'compiler_artifacts_sha256': digest(report / 'issuer-build.json'),
    'metadata_sha256': digest(report / 'cblc-metadata.json'),
    'executable': str(executable), 'executable_sha256': digest(executable),
    'fixture_alias': str(alias), 'resolved_alias': str(alias.resolve(strict=True)),
}, indent=2, sort_keys=True) + '\n')
PY
fi
check_executables() {
    sha256sum --check --strict "$report_dir/issuer-executable.sha256"
    if [[ $fixture == full-extension ]]; then
        test -L target/debug/examples/wave_verifier
        test "$(realpath target/debug/examples/wave_verifier)" = "$(realpath "$CBLC_WAVE_VERIFIER")"
        sha256sum --check --strict "$report_dir/wave-verifier-executable.sha256"
    fi
}
# No optional optimizer/tool installation; this is not browser/performance acceptance.
run python3 .ci/g2-candidates.py select-patches cwlt wasm
run "$G2_WASM_PACK_BINARY" build "$wallet_dir" --target web --release --mode no-install --no-opt --out-dir "$PWD/.extension-wasm" -- --locked
run python3 .ci/g2-candidates.py verify-patches cwlt
sha256sum --check --strict "$report_dir/cargo-locks.sha256"
run python3 .ci/g2-candidates.py select-patches cblc proof
export CBLC_EXTENSION_DIRECTORY="$report_dir/public"
run node runtime/extensions/compile.mjs
fixture_args=(--record-diagnostic)
if [[ $fixture == full-extension ]]; then fixture_args=(); fi
check_executables
run node tests/extensions-proof.mjs "${fixture_args[@]}"
check_executables
run node tests/replay-extensions.mjs "${fixture_args[@]}"
check_executables
run python3 .ci/g2-candidates.py check
sha256sum --check --strict "$report_dir/cargo-locks.sha256"
sha256sum --check --strict "$report_dir/npm-lock.sha256"
