#!/usr/bin/env bash
# Exact retained Rust peer replay only; no Cargo, compilation, or prover call.
set -euo pipefail
: "${CI:?CI only}" "${CARGO_HOME:?}" "${CI_COMMIT_SHA:?}" "${SOURCE_SHA256:?}" "${SOURCE_ARCHIVE:?}"
: "${CI_REPOSITORY_URL:?}" "${DEPENDENCY_CLOSURE_MANIFEST:?}" "${DEPENDENCY_CLOSURE_SHA256:?}"
: "${G2_CODEC_SOURCE_ARCHIVE:?}" "${G2_CODEC_SOURCE_SHA256:?}"
: "${G2_CWLT_SOURCE_ARCHIVE:?}" "${G2_CWLT_SOURCE_SHA256:?}"
: "${G2_WAVE_EVIDENCE_ARCHIVE:?}" "${G2_WAVE_EVIDENCE_SHA256:?}"
: "${G2_WAVE_PEER_ARCHIVE:?}" "${G2_WAVE_PEER_SHA256:?}"
[[ "${CI_JOBS:?}" =~ ^[12]$ ]] && [[ "${CI_TEST_THREADS:?}" =~ ^[12]$ ]]
[[ "${CI_MEMORY_MB:?}" =~ ^[1-9][0-9]{0,4}$ ]] && ((CI_MEMORY_MB <= 16384))
export UV_THREADPOOL_SIZE=2 RAYON_NUM_THREADS=2 OMP_NUM_THREADS=2
finish() {
    code=$?
    trap - EXIT
    set +e
    if [[ -f "$report_dir/replay-input-bindings.json" ]]; then
        timeout --kill-after=5s 30s python3 .ci/g2-wave-inputs.py peer-check 2>&1 | tee -a "$report_dir/check.log"
        guard_code=$?
        if ((code == 0 && guard_code != 0)); then code=$guard_code; fi
    fi
    python3 - "$report_dir" "$code" <<'PY'
import hashlib, json, os, pathlib, sys
root, code = pathlib.Path(sys.argv[1]), int(sys.argv[2])
files = {}
for path in root.rglob('*'):
    if path.is_file():
        with path.open('rb') as stream:
            files[str(path.relative_to(root))] = hashlib.file_digest(stream, 'sha256').hexdigest()
receipt = {'schema': 1, 'scope': 'g2-public-wave-peer-diagnostic',
           'status': 'passed' if code == 0 else 'failed', 'exit_code': code,
           'commit': os.environ['CI_COMMIT_SHA'], 'source_sha256': os.environ['SOURCE_SHA256'],
           'repository': os.environ['CI_REPOSITORY_URL'],
           'observed_main_closure_sha256': os.environ['DEPENDENCY_CLOSURE_SHA256'],
           'evidence_sha256': os.environ['G2_WAVE_EVIDENCE_SHA256'],
           'codec_sha256': os.environ['G2_CODEC_SOURCE_SHA256'],
           'peer_archive_sha256': os.environ['G2_WAVE_PEER_SHA256'],
           'codec_commit': '6e8755f2858dac3f72d61d8450158c2cd20d7d7c',
           'artifacts': files, 'proof_regeneration': False, 'rust_build': False,
           'product_acceptance': False, 'reconstructed_request_is_authority': False,
           'resources': {k: os.environ.get(k) for k in ['CI_JOBS', 'CI_TEST_THREADS', 'CI_MEMORY_MB']}}
(root / 'diagnostic.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps({'diagnostic_receipt': str(root / 'diagnostic.json'), 'status': receipt['status']}))
PY
    receipt_code=$?
    if ((code == 0 && receipt_code != 0)); then code=$receipt_code; fi
    exit "$code"
}
if [[ $# == 0 ]]; then
    mkdir -p "$CARGO_HOME/ccid-artifacts/cblc-g2-wave-peer-replay"
    report_dir=$(mktemp -d "$CARGO_HOME/ccid-artifacts/cblc-g2-wave-peer-replay/$CI_COMMIT_SHA.XXXXXXXX")
    export CBLC_DIAGNOSTIC_OUTPUT="$report_dir"
    trap finish EXIT
    # Only the child group receives the deadline; this parent retains failures.
    set +e
    timeout --kill-after=15s 600s bash .ci/g2-wave-peer.sh --child 2>&1 | tee "$report_dir/check.log"
    statuses=("${PIPESTATUS[@]}")
    code=${statuses[0]}
    if ((code == 0 && statuses[1] != 0)); then code=${statuses[1]}; fi
    exit "$code"
fi
[[ $# == 1 && $1 == --child ]]
report_dir=${CBLC_DIAGNOSTIC_OUTPUT:?parent supervision required}
test -d "$report_dir"
cp "$DEPENDENCY_CLOSURE_MANIFEST" "$report_dir/observed-main-closure.json"
node --version > "$report_dir/node.txt"
npm --version > "$report_dir/npm.txt"
cp experiments/private-accounting/package-lock.json "$report_dir/package-lock.json"
npm ci --prefix "$PWD/experiments/private-accounting" --workspaces=false --ignore-scripts --no-audit --no-fund
test ! -e node_modules
ln -s experiments/private-accounting/node_modules node_modules
export BB_BINARY_PATH="$PWD/node_modules/@aztec/bb.js/build/amd64-linux/bb"
test -x "$BB_BINARY_PATH"
python3 .ci/g2-wave-inputs.py peer-unpack
node --v8-pool-size=2 .ci/g2-wave-peer.mjs
