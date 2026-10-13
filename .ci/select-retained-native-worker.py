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
PINNED = "44452b71ef1d79c60a3f61f128aebefaeb43babee55b0ce701f2f7219d8a22d6"
retained = root / "gather-record-fixture-retained" / PINNED
source = (retained if retained.is_dir() else root / "gather-record-fixture").resolve(strict=True)
metadata = source / "worker.json"
if digest(metadata, 65536) != PINNED:
    raise SystemExit("Original verification worker receipt differs")
receipt = json.loads(metadata.read_text())
expected = {
    "sourceCommit": "829489a47cb3b2798830921591416b73f09ccafa",
    "sourceArchiveSha256": "a7ec3d644b0b7c2788a8e6f1d9ebf32846bd9daca16903eeb7bb80b5f8fc8681",
    "cargoLockSha256": "d7f6214c356eda32cbd0c23fea65c22048902b8962494950cebe5c77cdd763ac",
    "nativeSdkSha256": "d3d70f5c3a9e55d241ce8842b2a8fd254ca651bcd38a8434faa9f363f68e756f",
    "workerSha256": "20136479f31369532345b1e56e0b95a2e4c82803e03b352b1d19b1cc18eab87a",
    "workerBytes": 68155080,
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
