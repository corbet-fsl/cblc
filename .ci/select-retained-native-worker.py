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
source = (root / "gather-record-fixture").resolve(strict=True)
metadata = source / "worker.json"
if digest(metadata, 65536) != "7270351d40c1ed49b1499ec82e59449e6d28ca715d5590485dee56e7ef757ff2":
    raise SystemExit("Original verification worker receipt differs")
receipt = json.loads(metadata.read_text())
expected = {
    "sourceCommit": "d6014acbef63f4cd0929b20091884dd422421fc3",
    "sourceArchiveSha256": "4b82df6659ae25f6cbfc509089baf7d6f8a3458975eea28f9e9044ac4d2d8157",
    "cargoLockSha256": "d0a8d444db7322653d92cbfb491e529a2b1a919917e1751ba03e1d55f3b3f172",
    "nativeSdkSha256": "d3d70f5c3a9e55d241ce8842b2a8fd254ca651bcd38a8434faa9f363f68e756f",
    "workerSha256": "747881540393b97845026c4c7c1831527a9356d1157aaa91ad2edd05599fb000",
    "workerBytes": 65702792,
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
