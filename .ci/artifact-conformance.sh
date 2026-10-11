#!/usr/bin/env bash
# Original public artifact/proof relation only, not current Rust host acceptance.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing original artifact destination}"
python3 -B .ci/check-native-sdk.py
npm ci --ignore-scripts --no-audit --no-fund
CBLC_CONFORMANCE_NATIVE_WORKER="$(python3 -B .ci/select-retained-native-worker.py)"
export CBLC_CONFORMANCE_NATIVE_WORKER
export CBLC_EXTENSION_DIRECTORY="$PWD/.artifact-conformance"
test ! -e "$CBLC_EXTENSION_DIRECTORY" || { echo 'Existing conformance output refuses overwrite' >&2; exit 2; }
node runtime/extensions/compile.mts --record-epoch
node tests/extensions-proof.mts --record-epoch-artifacts
# Only public files exist here; private witnesses never enter this directory.
: "${CI_COMMIT_SHA:?Missing original source identity}"
case "$CI_COMMIT_SHA" in *[!0-9a-f]*|'') exit 2;; esac
test "${#CI_COMMIT_SHA}" -eq 40
destination="$ARTIFACT_ROOT/$CI_COMMIT_SHA/artifact-conformance"
test ! -e "$destination" || { echo 'Retained conformance group refuses overwrite' >&2; exit 2; }
mkdir -p "$destination/setup"
for file in circuits.json keys.json manifest.json; do
  cp -- "$CBLC_EXTENSION_DIRECTORY/$file" "$destination/$file"
done
for file in g1.dat g2.dat; do
  cp -- "$CBLC_EXTENSION_DIRECTORY/setup/$file" "$destination/setup/$file"
done
cp artifact-conformance-worker.json "$destination/worker-receipt.json"
python3 -B - "$destination" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys

def bounded(path, maximum):
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Public retained file bound")
    return data

def sha(data):
    return hashlib.sha256(data).hexdigest()

destination = Path(sys.argv[1])
manifest_sha = sha(bounded(destination / "manifest.json", 65536))
request_bytes = bounded(Path("tests/holder/fixtures/alpha-native-request.json"), 65536)
request_sha = sha(request_bytes)
if request_sha != "197281e27a68c485c51d556b1d10cbefdd21b0ba471b9c5a03afa86d4af0c897":
    raise ValueError("Reviewed alpha configuration differs")
request = json.loads(request_bytes)
matches = []
for count, path in enumerate(Path(os.environ["ARTIFACT_ROOT"]).glob(f"alpha-activation-{manifest_sha}-*.json")):
    if count >= 8:
        raise ValueError("Public activation selection bound")
    data = bounded(path, 4 * 1024 * 1024)
    value = json.loads(data)
    if value.get("configuration") != request:
        continue
    if value.get("manifestSha256") != manifest_sha or value.get("authority") != "none":
        raise ValueError("Public activation association differs")
    if value["producer"]["nativeVerification"]["positiveVerdict"] is not True:
        raise ValueError("Original native verification missing")
    matches.append((path.name, data))
if len(matches) != 1:
    raise ValueError("Exact configured activation unavailable")
name, data = matches[0]
(destination / name).write_bytes(data)
# Preserve the original retained portable convention. A trusted consumer must
# rebase directory under this exact manifest pin before calling loadArtifacts.
(destination / "config.json").write_text(json.dumps({"directory": ".", "manifestSha256": manifest_sha}) + "\n")
(destination / "index.json").write_text(json.dumps({
    "version": 1, "purpose": "original-artifact-conformance", "authority": "none",
    "manifestSha256": manifest_sha,
    "configurationSha256": request_sha,
    "activation": {"file": name, "sha256": sha(data)},
    "workerReceiptSha256": sha(bounded(destination / "worker-receipt.json", 65536)),
}, sort_keys=True) + "\n")
PY
sha256sum "$destination/manifest.json" "$destination/circuits.json" "$destination/keys.json"
