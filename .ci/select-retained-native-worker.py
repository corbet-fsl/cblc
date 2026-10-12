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
# The first pinned worker (cblc d6014ac, receipt 7270351d...) was only ever kept in the live producer
# directory, which every verify run rewrites; its bytes no longer exist. The immutable retained capture
# below (cblc 6232481, retain-record-fixture.py) replaces it. A pin change: reviewed before it is trusted.
PINNED = "23cf333ef4c1bb9acc401e3cf448528978d960fe793dbcc50da7a1ef54f6b212"
source = (root / "gather-record-fixture-retained" / PINNED).resolve(strict=True)
metadata = source / "worker.json"
if digest(metadata, 65536) != PINNED:
    raise SystemExit("Original verification worker receipt differs")
receipt = json.loads(metadata.read_text())
expected = {
    "sourceCommit": "62324819462d67a39f71e41216967a2b1e1600ce",
    "sourceArchiveSha256": "1b1a8dd61d4db763becf01f8b2e989f85791d2b3b588f5edd912f2c815b4399a",
    "cargoLockSha256": "85ee6e30cc3d8ce6033a0cb415f265db95e0cd4f93f0dcf9cdd30bc8b2270f99",
    "nativeSdkSha256": "d3d70f5c3a9e55d241ce8842b2a8fd254ca651bcd38a8434faa9f363f68e756f",
    "workerSha256": "5c5c69cca3ccc1d00e12d7d75bd431b79d68864b88e3c5ba18284c77f2ac46f9",
    "workerBytes": 68078712,
    "workerMode": 493,
}
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
