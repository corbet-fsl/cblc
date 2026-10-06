#!/usr/bin/env bash
# Diagnostic composition of explicit candidates; never ordinary main qualification.
set -euo pipefail
fixture=record-diagnostic
if [[ $# == 1 && $1 == --full-extension ]]; then
    fixture=full-extension
elif [[ $# == 1 && $1 == --proof-time ]]; then
    fixture=proof-time
    export RECORD_PROOF_BROWSER=1
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
source_root="$(pwd -P)"
wallet_dir="$source_root/experiments/private-accounting/node_modules/@corbet-labs/cwlt"
codec_dir="$source_root/experiments/private-accounting/node_modules/@corbet-labs/czkp"
finish() {
    code=$?
    if [[ -f Cargo.lock ]]; then cp Cargo.lock "$report_dir/final-Cargo.lock"; fi
    if [[ -f "$wallet_dir/Cargo.lock" ]]; then
        cp "$wallet_dir/Cargo.lock" "$report_dir/final-cwlt-Cargo.lock"
    fi
    if [[ -f "$codec_dir/Cargo.lock" ]]; then
        cp "$codec_dir/Cargo.lock" "$report_dir/final-czkp-Cargo.lock"
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
scope = 'g2-' + fixture
receipt = {'schema': 1, 'scope': scope,
           'extension_fixture': fixture,
           'status': 'passed' if code == 0 else 'failed', 'exit_code': code,
           'commit': os.environ['CI_COMMIT_SHA'], 'source_sha256': os.environ['SOURCE_SHA256'],
           'repository': os.environ['CI_REPOSITORY_URL'],
           'dependency_closure_sha256': os.environ['DEPENDENCY_CLOSURE_SHA256'],
           'source_freshness': json.loads((root / 'source-provenance.json').read_text())
               if (root / 'source-provenance.json').exists() else {'status': 'see closure manifest'},
           'candidate_sources': 'candidate-sources.json',
           'candidate_patches': {name: f'candidate-patches-{name}.toml' for name in ['cblc', 'cwlt', 'czkp']},
           'artifacts': files, 'product_acceptance': False, 'full_suite': False,
           'browser_evidence': fixture == 'proof-time' and code == 0, 'wasm_opt_postprocessing': False,
           'resolution_only_candidates': {
               name: {'compiled': False if code == 0 else None, 'qualified': False}
               for name in ['cpsd']},
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
run node --test "$codec_dir/tests/abi.test.mjs" "$codec_dir/tests/record.test.mjs" "$codec_dir/tests/node-worker-entry.test.mjs"
if [[ $fixture == proof-time ]]; then
    printf '%s  %s\n' "$G2_CVLT_SOURCE_SHA256" "$G2_CVLT_SOURCE_ARCHIVE" | sha256sum --check --strict
    mkdir .g2-vault
    tar --no-same-owner -xf "$G2_CVLT_SOURCE_ARCHIVE" -C .g2-vault
    chromium --version > "$report_dir/chromium.txt"
    sha256sum .g2-vault/hosting/isolation.mjs > "$report_dir/vault-hosting.sha256"
fi
cp "$wallet_dir/Cargo.lock" "$report_dir/baseline-cwlt-Cargo.lock"
cp "$codec_dir/Cargo.lock" "$report_dir/baseline-czkp-Cargo.lock"
# Each original workspace resolves once and freezes immediately before any test.
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
sha256sum "$wallet_dir/Cargo.lock" > "$report_dir/cwlt-resolved-lock.sha256"
run python3 .ci/g2-candidates.py select-patches czkp resolve
run cargo update --manifest-path "$codec_dir/Cargo.toml"
sha256sum --check --strict "$report_dir/cblc-resolved-lock.sha256" "$report_dir/cwlt-resolved-lock.sha256"
cp "$codec_dir/Cargo.lock" "$report_dir/czkp-Cargo.lock"
sha256sum "$codec_dir/Cargo.lock" > "$report_dir/czkp-resolved-lock.sha256"
date -u +%FT%TZ > "$report_dir/czkp-resolved-at.txt"
sha256sum Cargo.lock "$wallet_dir/Cargo.lock" "$codec_dir/Cargo.lock" > "$report_dir/cargo-locks.sha256"
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
    # Preserve all three resolved locks and restore their exact bytes after inspection.
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
metadata czkp --manifest-path "$codec_dir/Cargo.toml" --all-features --format-version 1
run python3 .ci/g2-candidates.py select-patches cblc check
run python3 .ci/g2-candidates.py check
# Original matched upstream CLI acquisition, scoped to this job's artifact path.
run bash .ci/g2-wasm-runner.sh
export PATH="$report_dir/runner:$PATH"
export WASM_PACK_CACHE="$PWD/.g2-wasm-pack-cache"
mkdir "$WASM_PACK_CACHE"
# Codec integration tests need their original workspace and its own frozen lock.
run python3 .ci/g2-candidates.py select-patches czkp codec-native
run python3 .ci/g2-candidates.py check-codec-source
cargo test --locked --all-features --manifest-path "$codec_dir/Cargo.toml" --test record \
    --no-run --message-format=json > "$report_dir/codec-native-build.json"
codec_native=$(python3 .ci/g2-candidates.py codec-artifact native)
codec_native_test() { (cd "$codec_dir"; "$codec_native" --test-threads="$CI_TEST_THREADS"); }
run codec_native_test | tee "$report_dir/codec-native-test.log"
run python3 .ci/g2-candidates.py verify-codec-artifact native
run python3 .ci/g2-candidates.py select-patches czkp codec-wasm
run python3 .ci/g2-candidates.py check-codec-source
cargo test --locked --all-features --manifest-path "$codec_dir/Cargo.toml" --test record \
    --target wasm32-unknown-unknown --no-run --message-format=json > "$report_dir/codec-wasm-build.json"
codec_wasm=$(python3 .ci/g2-candidates.py codec-artifact wasm)
codec_abi=$(python3 - "$codec_dir/Cargo.lock" <<'PYCODEC'
import sys, tomllib
versions = {p['version'] for p in tomllib.load(open(sys.argv[1], 'rb'))['package'] if p['name'] == 'wasm-bindgen'}
assert len(versions) == 1
print(versions.pop())
PYCODEC
)
codec_runner_dir="$report_dir/runner"
if [[ "$("$codec_runner_dir/wasm-bindgen" --version)" != "wasm-bindgen $codec_abi" ]]; then
    mkdir "$report_dir/codec"
    (cd "$codec_dir"; CI_ACCEPTANCE_ARTIFACTS="$report_dir/codec" bash "$source_root/.ci/g2-wasm-runner.sh")
    codec_runner_dir="$report_dir/codec/runner"
fi
test "$("$codec_runner_dir/wasm-bindgen" --version)" = "wasm-bindgen $codec_abi"
sha256sum "$codec_runner_dir/wasm-bindgen" "$codec_runner_dir/wasm-bindgen-test-runner" > "$report_dir/codec-runner.sha256"
python3 - "$report_dir" "$codec_runner_dir" "$codec_abi" <<'PYCODEC'
import hashlib, json, pathlib, sys
report, runner, version = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
(report / 'codec-runner-binding.json').write_text(json.dumps({
    'wasm_bindgen_version': version, 'codec_lock_sha256': digest(report / 'czkp-Cargo.lock'),
    'runner_directory': str(runner), 'upstream_artifacts_sha256': digest(runner / 'runner-artifact.sha256'),
    'test_runner_sha256': digest(runner / 'wasm-bindgen-test-runner'),
    'wasm_bindgen_sha256': digest(runner / 'wasm-bindgen'),
}, indent=2, sort_keys=True) + '\n')
PYCODEC
sha256sum --check --strict "$report_dir/codec-runner.sha256"
run python3 .ci/g2-candidates.py verify-codec-artifact wasm
codec_wasm_test() { (cd "$codec_dir"; "$codec_runner_dir/wasm-bindgen-test-runner" "$codec_wasm"); }
run codec_wasm_test | tee "$report_dir/codec-wasm-test.log"
sha256sum --check --strict "$report_dir/codec-runner.sha256"
run python3 .ci/g2-candidates.py verify-codec-artifact wasm
python3 - "$report_dir" <<'PYCODEC'
import json, pathlib, re, sys
report = pathlib.Path(sys.argv[1])
for target in ['native', 'wasm']:
    text = (report / f'codec-{target}-test.log').read_text()
    if not re.search(r'test result: ok\. 5 passed; 0 failed; 0 ignored;', text) or '0 filtered out' not in text:
        raise SystemExit('Expected all five record integration tests: ' + target)
(report / 'codec-test-results.json').write_text(json.dumps({
    'native_tests_passed': 5, 'node_wasm_tests_passed': 5,
    'test_target': 'record', 'product_acceptance': False,
}, indent=2, sort_keys=True) + '\n')
PYCODEC
sha256sum --check --strict "$report_dir/cargo-locks.sha256"
run python3 .ci/g2-candidates.py select-patches cblc fmt
run cargo fmt --all -- --check
run cargo test --locked --all-features --lib
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
    # Observe the actual first public Wave peer inside this full fixture. This
    # never substitutes a retained proof or turns a refusal into acceptance.
    export CBLC_CAPTURE_FULL_WAVE=1
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
if [[ $fixture == proof-time ]]; then
    run cargo fmt --manifest-path "$wallet_dir/Cargo.toml" --all -- --check
    run cargo test --locked --manifest-path "$wallet_dir/Cargo.toml" -p cwlt-engine --tests
    run cargo test --locked --manifest-path "$wallet_dir/Cargo.toml" --features record --test record
    run cargo clippy --locked --manifest-path "$wallet_dir/Cargo.toml" --features record --lib -- -D warnings
    run node --test "$codec_dir/tests/record.test.mjs"
fi
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
