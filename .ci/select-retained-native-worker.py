"""Select only the original authenticated public verification worker capture."""
import hashlib
import json
import os
from pathlib import Path


def digest(path, maximum):
    value = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > maximum:
                raise ValueError("Original worker file bound")
            value.update(chunk)
    return value.hexdigest()


root = Path(os.environ["ARTIFACT_ROOT"])
if not root.is_absolute():
    raise SystemExit("Original artifact destination unavailable")
# The live producer directory is rewritten by every verify run; the pinned capture is kept
# immutably under its own receipt digest (retain-record-fixture.py).
PINNED = "e55d4cafadb748f4e24a7a581208407c2fcb32ea74a1ae37532167e9054c4925"
retained = root / "gather-record-fixture-retained" / PINNED
source = (retained if retained.is_dir() else root / "gather-record-fixture").resolve(strict=True)
metadata = source / "worker.json"
if digest(metadata, 65536) != PINNED:
    raise SystemExit("Original verification worker receipt differs")
receipt = json.loads(metadata.read_text())
expected = {
    "sourceCommit": "e5514337959c4aacb3e9d7f678e3f45898b61061",
    "sourceArchiveSha256": "7996f496e02473b3c4b291c2cfcaba538fc8cd7c82970499b1f35c03da63c231",
    "cargoLockSha256": "d39f33b094bd211e4320335f345237fd54f847f813e7905298c00a6169121a2a",
    "nativeSdkSha256": "d3d70f5c3a9e55d241ce8842b2a8fd254ca651bcd38a8434faa9f363f68e756f",
    "workerSha256": "7d90df5d29d222545bebba3e10cdbbdeac974856bfe8ae27a235d8b31b8e42e6",
    "workerBytes": 68211552,
    "workerMode": 493,
}
print("CBLC-WORKER-RECEIPT " + json.dumps({key: receipt.get(key) for key in expected}, sort_keys=True), file=__import__("sys").stderr)
if any(receipt[key] != value for key, value in expected.items()):
    raise SystemExit("Original native verifier identity differs")
worker = (source / "worker").resolve(strict=True)
if worker.parent != source or not worker.is_file() or worker.stat().st_size != receipt["workerBytes"]:
    raise SystemExit("Original native verifier path differs")
if worker.stat().st_mode & 0o777 != receipt["workerMode"] or digest(worker, 512 * 1024 * 1024) != receipt["workerSha256"]:
    raise SystemExit("Original native verifier bytes differ")
files = receipt["runtime"]["files"]
if not 1 <= len(files) <= 32:
    raise SystemExit("Original runtime closure bound")
for file in files:
    path = Path(file["path"])
    if not path.is_absolute() or not path.is_file() or digest(path, 512 * 1024 * 1024) != file["sha256"]:
        raise SystemExit("Original verification runtime differs")
Path("artifact-conformance-worker.json").write_text(json.dumps({
    "version": 1, "purpose": "original-raw-native-verifier-conformance",
    "metadataSha256": digest(metadata, 65536), **expected,
}, sort_keys=True) + "\n")
print(worker)
