#!/usr/bin/env python3
"""Retain each genuine native record capture once, under its own digest.

The producer directory ``gather-record-fixture`` is rewritten by every run. A
consumer pins a capture by the SHA-256 of its ``worker.json``; that capture is
kept, immutable, in ``gather-record-fixture-retained/<digest>/``. An existing
digest directory is verified and left untouched, never overwritten.

The same run's native startup capture ``native-startup-fixture`` is kept the same
way in ``native-startup-fixture-retained/<digest>/``, addressed by the SHA-256 of
its ``startup-artifacts.json``.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify(directory):
    """Check the capture against its own receipt; return the receipt digest."""
    metadata_path = directory / "worker.json"
    metadata_bytes = metadata_path.read_bytes()
    if len(metadata_bytes) > 65536:
        raise ValueError("Worker receipt exceeds its bound")
    metadata = json.loads(metadata_bytes)
    worker = directory / "worker"
    info = worker.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size != metadata["workerBytes"]
            or digest(worker) != metadata["workerSha256"]):
        raise ValueError("Worker bytes differ from their receipt")
    files = metadata["artifactFiles"]
    if not files:
        raise ValueError("The capture lists no artifact files")
    for name, expected in files.items():
        path = directory / name
        if Path(name).is_absolute() or ".." in Path(name).parts or digest(path) != expected:
            raise ValueError(f"Artifact differs from its receipt: {name}")
    return hashlib.sha256(metadata_bytes).hexdigest()


STARTUP_METADATA = "startup-artifacts.json"


def verify_startup(directory):
    """Check the native startup capture against its own metadata; return its digest."""
    metadata_bytes = (directory / STARTUP_METADATA).read_bytes()
    if len(metadata_bytes) > 65536:
        raise ValueError("Startup metadata exceeds its bound")
    files = json.loads(metadata_bytes)["files"]
    if not files:
        raise ValueError("The startup capture lists no files")
    for name, expected in files.items():
        relative = Path(name)
        path = directory / relative
        info = path.lstat()
        if (relative.is_absolute() or ".." in relative.parts or not stat.S_ISREG(info.st_mode)
                or info.st_size != expected["bytes"] or digest(path) != expected["sha256"]):
            raise ValueError(f"Startup file differs from its metadata: {name}")
    return hashlib.sha256(metadata_bytes).hexdigest()


def retain(source, root, check=None):
    check = check or verify
    receipt = check(source)
    root.mkdir(parents=True, exist_ok=True)
    destination = root / receipt
    if not destination.exists():
        incoming = Path(tempfile.mkdtemp(prefix=".incoming-", dir=root))
        try:
            copy = incoming / "capture"
            shutil.copytree(source, copy)
            if check(copy) != receipt:
                raise ValueError("Capture changed while it was retained")
            try:
                os.rename(copy, destination)
            except FileExistsError:
                pass
        finally:
            shutil.rmtree(incoming, ignore_errors=True)
    # Whether new or already present, the retained capture must be exactly this one.
    if check(destination) != receipt:
        raise ValueError("Retained capture differs from its digest")
    return receipt


if __name__ == "__main__":
    artifacts = Path(os.environ["ARTIFACT_ROOT"])
    if not artifacts.is_absolute():
        sys.exit("An absolute ARTIFACT_ROOT is required")
    print(f"CBLC_RETAINED_RECORD_FIXTURE {retain(artifacts / 'gather-record-fixture', artifacts / 'gather-record-fixture-retained')}")
    startup = artifacts / "native-startup-fixture"
    if startup.exists():
        print(f"CBLC_RETAINED_STARTUP_FIXTURE {retain(startup, artifacts / 'native-startup-fixture-retained', verify_startup)}")
