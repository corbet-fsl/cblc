#!/usr/bin/env python3
"""A retained capture is created once and never overwritten."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location("retain", Path(__file__).with_name("retain-record-fixture.py"))
retain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retain)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def capture(directory, marker):
    (directory / "setup").mkdir(parents=True)
    worker = b"worker-" + marker
    (directory / "worker").write_bytes(worker)
    (directory / "keys.json").write_bytes(b"keys-" + marker)
    (directory / "setup" / "g2.dat").write_bytes(b"g2")
    metadata = {"version": 1, "workerBytes": len(worker), "workerSha256": sha(worker),
                "artifactFiles": {"keys.json": sha(b"keys-" + marker), "setup/g2.dat": sha(b"g2")}}
    (directory / "worker.json").write_text(json.dumps(metadata, sort_keys=True))


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    source, retained = root / "gather-record-fixture", root / "retained"
    capture(source, b"one")
    first = retain.retain(source, retained)
    assert first == sha((source / "worker.json").read_bytes())
    assert retain.retain(source, retained) == first
    # A later producer run replaces the working directory; the first capture stays.
    import shutil
    shutil.rmtree(source)
    capture(source, b"two")
    second = retain.retain(source, retained)
    assert second != first
    assert (retained / first / "worker").read_bytes() == b"worker-one"
    assert (retained / second / "worker").read_bytes() == b"worker-two"
    assert sorted(path.name for path in retained.iterdir()) == sorted([first, second])
    # Tampering with the retained copy is detected, not repaired by overwriting.
    (retained / first / "keys.json").write_bytes(b"tampered")
    try:
        retain.retain(source, retained)
        capture_two = True
    except ValueError:
        capture_two = False
    assert capture_two
    shutil.rmtree(source)
    capture(source, b"one")
    try:
        retain.retain(source, retained)
        raise SystemExit("Tampered retained capture was accepted")
    except ValueError:
        pass
    assert (retained / first / "keys.json").read_bytes() == b"tampered"
print("retained record fixture checks passed")
