#!/usr/bin/env python3
"""Refuse an upstream Rust SDK/static-library ABI mismatch before compiling."""
import json
from pathlib import Path
import re
import tomllib


def check(lock, artifact):
    version = artifact.get("version")
    digest = artifact.get("sha256")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Native artifact needs a stable upstream version")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Native artifact needs a SHA-256 digest")
    versions = [p["version"] for p in lock.get("package", []) if p["name"] == "barretenberg-rs"]
    if versions != [version]:
        raise ValueError("Locked barretenberg-rs must exactly match the authenticated native artifact")


if __name__ == "__main__":
    check(tomllib.loads(Path("Cargo.lock").read_text()),
          json.loads(Path(".ci/native-sdk.json").read_text()))
    print("Native SDK and authenticated static artifact versions match")
