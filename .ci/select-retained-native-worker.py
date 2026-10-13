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
PINNED = "a5bf61f841533ef711a78d06384fe93bc5bd02d761baffaeabb5a85a271cb04b"
retained = root / "gather-record-fixture-retained" / PINNED
source = (retained if retained.is_dir() else root / "gather-record-fixture").resolve(strict=True)
metadata = source / "worker.json"
if digest(metadata, 65536) != PINNED:
    raise SystemExit("Original verification worker receipt differs")
receipt = json.loads(metadata.read_text())
expected = {
    "sourceCommit": "1be151807376447a1f0e0fe6d66040533f3ca0fd",
    "sourceArchiveSha256": "c1441690c4f28df9c6059a4c473b53ffefe2b9b15ed7550d827baafb8b931bcb",
    "cargoLockSha256": "daec7730c7f33d48d4e7c11b73ecd7df94a4854dc1b7b477e5eec0a6237f0027",
    "nativeSdkSha256": "d3d70f5c3a9e55d241ce8842b2a8fd254ca651bcd38a8434faa9f363f68e756f",
    "workerSha256": "fd4c24cc01f158f4362c21c642f57021b60854c6d6b06afea85d44686c4fe951",
    "workerBytes": 68078712,
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
