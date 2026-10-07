#!/usr/bin/env bash
# Only original codec checks and record_epoch compilation. No Cargo resolution,
# private witnesses, proof execution, or product qualification happens here.
set -euo pipefail
: "${CI:?CI only}" "${CARGO_HOME:?persistent receipt root required}" "${CI_COMMIT_SHA:?}" "${SOURCE_SHA256:?}" "${CI_REPOSITORY_URL:?}"
: "${G2_CODEC_SOURCE_ARCHIVE:?}" "${G2_CODEC_SOURCE_SHA256:?}"
[[ "${CI_JOBS:?}" =~ ^[12]$ ]]
[[ "${CI_TEST_THREADS:?}" =~ ^[12]$ ]]
[[ "${CI_MEMORY_MB:?}" =~ ^[0-9]+$ ]] && ((CI_MEMORY_MB > 0 && CI_MEMORY_MB <= 16384))
export UV_THREADPOOL_SIZE=2 RAYON_NUM_THREADS=2 OMP_NUM_THREADS=2
codec_commit=b1093a02efbf5597638206397f97976ecd993a39
export G2_CODEC_COMMIT="$codec_commit"
mkdir -p "$CARGO_HOME/ccid-artifacts/cblc-g2-diagnostic"
report_dir=$(mktemp -d "$CARGO_HOME/ccid-artifacts/cblc-g2-diagnostic/$CI_COMMIT_SHA.XXXXXXXX")
export CBLC_DIAGNOSTIC_OUTPUT="$report_dir"
finish() {
    code=$?
    if [[ -f experiments/private-accounting/package-lock.json ]]; then
        cp experiments/private-accounting/package-lock.json "$report_dir/final-package-lock.json"
    fi
    python3 - "$report_dir" "$code" <<'PY'
import hashlib, json, os, pathlib, sys
root, code = pathlib.Path(sys.argv[1]), int(sys.argv[2])
files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
receipt = {'schema': 1, 'scope': 'g2-codec-and-record-compile-diagnostic',
           'status': 'passed' if code == 0 else 'failed', 'exit_code': code,
           'source': {'repository': os.environ['CI_REPOSITORY_URL'],
                      'commit': os.environ['CI_COMMIT_SHA'], 'sha256': os.environ['SOURCE_SHA256']},
           'codec': {'repository': 'https://git.corbet.ch/corbet-foss/czkp.git',
                     'commit': os.environ['G2_CODEC_COMMIT'], 'sha256': os.environ['G2_CODEC_SOURCE_SHA256'],
                     'identity': 'explicit diagnostic candidate; not observed main'},
           'resources': {k: os.environ.get(k) for k in ['CI_JOBS', 'CI_TEST_THREADS', 'CI_MEMORY_MB']},
           'artifacts': files, 'product_acceptance': False, 'proof_execution': False}
(root / 'diagnostic.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps({'diagnostic_receipt': str(root / 'diagnostic.json'), 'status': receipt['status']}))
PY
    exit "$code"
}
trap finish EXIT
run() { "$@" 2>&1 | tee -a "$report_dir/check.log"; }
node --version > "$report_dir/node.txt"
npm --version > "$report_dir/npm.txt"
cp experiments/private-accounting/package-lock.json "$report_dir/package-lock.json"
sha256sum experiments/private-accounting/package-lock.json > "$report_dir/lock.sha256"
printf '%s  %s\n' "$G2_CODEC_SOURCE_SHA256" "$G2_CODEC_SOURCE_ARCHIVE" | sha256sum --check --strict
test "$(git get-tar-commit-id < "$G2_CODEC_SOURCE_ARCHIVE")" = "$codec_commit"
test ! -e .g2-codec
mkdir .g2-codec
python3 - "$G2_CODEC_SOURCE_ARCHIVE" "$PWD/.g2-codec" <<'PY'
import pathlib, sys, tarfile
if pathlib.Path(sys.argv[1]).stat().st_size > 32 * 1024 * 1024:
    raise SystemExit('Diagnostic source archive byte bound')
with tarfile.open(sys.argv[1], mode='r:') as archive:
    members = archive.getmembers()
    if len(members) > 10000 or sum(m.size for m in members) > 32 * 1024 * 1024:
        raise SystemExit('Diagnostic source archive bound')
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
            raise SystemExit('Unsafe diagnostic source archive entry')
    archive.extractall(sys.argv[2], members=members, filter='data')
PY
run npm ci --prefix "$PWD/experiments/private-accounting" --workspaces=false --ignore-scripts --no-audit --no-fund
test ! -e node_modules
ln -s experiments/private-accounting/node_modules node_modules
run node --v8-pool-size=2 --test --test-concurrency=2 .g2-codec/tests/record.test.mjs
run node --v8-pool-size=2 .ci/compile-record.mjs
sha256sum --check --strict "$report_dir/lock.sha256"
