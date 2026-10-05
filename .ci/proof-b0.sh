#!/usr/bin/env bash
# Exact gates only. No private witnesses, setup loading, Cargo or proof timings.
set -euo pipefail
: "${CI:?CI only}" "${CARGO_HOME:?}" "${CI_COMMIT_SHA:?}" "${SOURCE_SHA256:?}"
mkdir -p "$CARGO_HOME/ccid-artifacts/cblc-proof-b0"
report_dir=$(mktemp -d "$CARGO_HOME/ccid-artifacts/cblc-proof-b0/$CI_COMMIT_SHA.XXXXXXXX")
export CBLC_DIAGNOSTIC_OUTPUT="$report_dir"
finish() {
  code=$?
  python3 - "$report_dir" "$code" <<'PY'
import json, os, pathlib, sys
root=pathlib.Path(sys.argv[1]); code=int(sys.argv[2])
receipt={'schema':1,'benchmark':'B0','commit':os.environ['CI_COMMIT_SHA'],
         'sourceArchiveSha256':os.environ['SOURCE_SHA256'],'exitCode':code,
         'adopted':False,'proofExecution':False,'qualified':False}
(root/'run.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'b0Receipt':str(root/'run.json'),'exitCode':code}))
PY
  exit "$code"
}
trap finish EXIT
run() { "$@" 2>&1 | tee -a "$report_dir/check.log"; }
cp experiments/private-accounting/package-lock.json "$report_dir/package-lock.json"
sha256sum experiments/private-accounting/package-lock.json > "$report_dir/lock.sha256"
run python3 .ci/proof-b0.py
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
export PROFILE_BACKEND=NativeUnixSocket
run node --test tests/proof-benchmarks/report.test.mjs
compile_status=0
run node tests/proof-benchmarks/compile.mjs "$report_dir/source-plan.json" "$report_dir/compiled" || compile_status=$?
run node tests/proof-benchmarks/profile.mjs "$report_dir/compiled/profile-plan.json" "$report_dir/gates"
sha256sum --check --strict "$report_dir/lock.sha256"
exit "$compile_status"
