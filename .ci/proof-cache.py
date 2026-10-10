#!/usr/bin/env python3
"""Cache complete fictional public proof fixtures, never verification verdicts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile

SCHEMA = "cblc-public-proof-fixtures-v1"
ROOTS = ("src", "tests", "examples", "circuits", "runtime", "experiments", ".cargo")
ROOT_FILES = {"Cargo.toml", "Cargo.lock", "package.json", "package-lock.json",
              "build.rs", "rust-toolchain", "rust-toolchain.toml"}
IMPLEMENTATION = (".ci/proof-cache.py", ".ci/replay-account-proofs.ts", ".ci/verify.sh", ".ci/check-fixture-suite.ts")
DIRECTORIES = (".proof-test", ".extension-test")
MAX_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_FILES = 256
MARKERS = (
    "Verified 6 real account proofs; rejected corrupted proofs and changed public inputs.",
    "Real proofs passed all three outcomes, rounding, forced ingestion, pin spend, zero-balance debt and negative scenarios",
    "Replayed 66 real-proof issuer calls and 29 adversaries with exact outcomes",
    "Real extension activation, signed scope, frontier, expiry and capacity refusals passed",
)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_size > MAX_FILE_BYTES:
        raise ValueError(f"Not a bounded regular file: {path}")
    return value


def file_record(path, name):
    value = regular(path)
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return {"path": name, "bytes": value.st_size, "sha256": hasher.hexdigest()}


def inputs(root):
    tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    names = sorted(name for name in tracked.decode().split("\0") if name and
                   (name in ROOT_FILES or name.split("/", 1)[0] in ROOTS))
    if not {"Cargo.toml", "Cargo.lock", "package.json", "package-lock.json"} <= set(names):
        raise ValueError("Missing locked fixture inputs")
    return [file_record(root / name, name) for name in names]


def context(root):
    value = {"schema": SCHEMA, "platform": [platform.system(), platform.machine()],
             "fixtureInputs": inputs(root),
             "cacheImplementation": [file_record(root / name, name) for name in IMPLEMENTATION]}
    return digest(encoded(value)), value


def inventory(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Payload must be a real directory")
    result = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("Symlink in fixture payload")
        for name in sorted(files):
            path = Path(directory) / name
            result.append(file_record(path, path.relative_to(root).as_posix()))
            if len(result) > MAX_FILES or sum(item["bytes"] for item in result) > MAX_BYTES:
                raise ValueError("Fixture payload exceeds cache bounds")
    return sorted(result, key=lambda item: item["path"])


def json_file(path):
    regular(path)
    return json.loads(path.read_text())


def complete_payload(root, allow_publication=False):
    if set(path.name for path in root.iterdir()) != set(DIRECTORIES):
        raise ValueError("Unexpected fixture roots")
    account, extension = (root / name for name in DIRECTORIES)
    required = {
        account: ("circuit.json", "vk.bin", "manifest.json", "config.json", "records.json", "ledger-records.json"),
        extension: ("circuits.json", "keys.json", "manifest.json", "config.json", "results.json", "public-trace.json", "source.txt"),
    }
    expected_paths = set(DIRECTORIES)
    for directory, names in required.items():
        prefix = directory.name
        expected_paths.add(f"{prefix}/setup")
        expected_paths.update(f"{prefix}/{name}" for name in names)
        for name in names:
            regular(directory / name)
        configuration = json_file(directory / "config.json")
        if set(configuration) != {"directory", "manifestSha256"} or not isinstance(configuration["directory"], str):
            raise ValueError("Invalid fixture configuration")
        if configuration["manifestSha256"] != digest((directory / "manifest.json").read_bytes()):
            raise ValueError("Fixture manifest digest mismatch")
        for item in json_file(directory / "manifest.json")["setup"]:
            name = item["name"]
            if not isinstance(name, str) or name in ("", ".", "..") or Path(name).name != name:
                raise ValueError("Invalid setup filename")
            expected_paths.add(f"{prefix}/setup/{name}")
            record = file_record(directory / "setup" / name, name)
            if record["bytes"] != item["bytes"] or record["sha256"] != item["sha256"]:
                raise ValueError("Setup artifact mismatch")
    if len(json_file(account / "records.json")) != 2 or len(json_file(account / "ledger-records.json")) != 6:
        raise ValueError("Incomplete account fixtures")
    trace = json_file(extension / "public-trace.json")
    if not isinstance(trace, list) or len(trace) != 66 or not json_file(extension / "results.json")["checks"]:
        raise ValueError("Incomplete extension trace")
    if allow_publication and (extension / "publication.json").exists():
        expected_paths.add(".extension-test/publication.json")
    inventory(root)
    actual_paths = {path.relative_to(root).as_posix() for path in root.rglob("*")}
    if actual_paths != expected_paths:
        raise ValueError("Unrecognized fixture files or directories")


def check_provenance(payload, provenance, fixture_inputs):
    if set(provenance) != {"generationCommit", "kind"} or not re.fullmatch(r"[0-9a-f]{40}", provenance["generationCommit"]):
        raise ValueError("Invalid generation provenance")
    if provenance["kind"] not in {"reviewed-interrupted-run-recovery", "completed-generation-and-native-replay"}:
        raise ValueError("Invalid provenance kind")
    lock_hash = next(item["sha256"] for item in fixture_inputs if item["path"] == "package-lock.json")
    expected = f"{provenance['generationCommit']}\n{lock_hash}  package-lock.json\n"
    if (payload / ".extension-test/source.txt").read_text() != expected:
        raise ValueError("Generation source/lock provenance mismatch")


def check_entry(entry, expected):
    if entry.is_symlink() or not entry.is_dir():
        raise ValueError("Cache entry must be a real directory")
    if set(path.name for path in entry.iterdir()) != {"complete.json", "evidence.log", "payload"}:
        raise ValueError("Partial or unexpected cache entry")
    marker = json_file(entry / "complete.json")
    if set(marker) != {"context", "key", "files", "provenance", "evidenceSha256"}:
        raise ValueError("Invalid completion marker")
    if marker["context"] != expected or marker["key"] != digest(encoded(expected)):
        raise ValueError("Fixture cache input mismatch")
    if file_record(entry / "evidence.log", "evidence.log")["sha256"] != marker["evidenceSha256"]:
        raise ValueError("Fixture provenance evidence mismatch")
    if inventory(entry / "payload") != marker["files"]:
        raise ValueError("Fixture cache content mismatch")
    complete_payload(entry / "payload")
    check_provenance(entry / "payload", marker["provenance"], expected["fixtureInputs"])
    return marker


def restore(root, cache):
    key, expected = context(root)
    entry = cache / key
    if not entry.exists() and not entry.is_symlink():
        print(f"Public proof fixture cache miss: {key}")
        return False
    marker = check_entry(entry, expected)
    for name in DIRECTORIES:
        if (root / name).exists() or (root / name).is_symlink():
            raise ValueError("Restore requires fresh fixture destinations")
    # Copy only after all original bytes and the complete inventory are checked.
    for name in DIRECTORIES:
        shutil.copytree(entry / "payload" / name, root / name)
        configuration = json_file(root / name / "config.json")
        configuration["directory"] = str((root / name).resolve())
        (root / name / "config.json").write_bytes(encoded(configuration))
    print(f"Restored complete public fixtures: {key}; generation {marker['provenance']['generationCommit']}")
    return True


def publish(root, cache, source, evidence, generation_commit, recovered):
    if source != root and not recovered:
        raise ValueError("Adopting another generation requires reviewed recovery")
    if not re.fullmatch(r"[0-9a-f]{40}", generation_commit):
        raise ValueError("Invalid generation commit")
    key, expected = context(root)
    # Recovery may apply newly reviewed cache machinery to old proof outputs;
    # every artifact-producing input must still match exactly, including locks.
    if inputs(source) != expected["fixtureInputs"]:
        raise ValueError("Generation source inputs differ from current inputs")
    actual_commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if actual_commit != generation_commit:
        raise ValueError("Generation source commit mismatch")
    regular(evidence)
    evidence_bytes = evidence.read_bytes()
    evidence_text = evidence_bytes.decode()
    if any(marker not in evidence_text for marker in MARKERS):
        raise ValueError("Missing completed generation and verification evidence")
    if generation_commit not in evidence_text:
        raise ValueError("Evidence is not bound to generation commit")
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / key
    if destination.exists() or destination.is_symlink():
        check_entry(destination, expected)
        return
    staging = Path(tempfile.mkdtemp(prefix=".incomplete-", dir=cache))
    try:
        payload = staging / "payload"
        payload.mkdir()
        for name in DIRECTORIES:
            inventory(source / name)  # Reject links/special files before copy.
            shutil.copytree(source / name, payload / name)
        # The adversary executable derives this file anew from the current
        # issuer. Keep only the generator's closed public-artifact inventory.
        complete_payload(payload, allow_publication=True)
        publication = payload / ".extension-test/publication.json"
        if publication.exists():
            publication.unlink()
        complete_payload(payload)
        files = inventory(payload)
        (staging / "evidence.log").write_bytes(evidence_bytes)
        marker = {"context": expected, "key": key, "files": files,
                  "provenance": {"generationCommit": generation_commit,
                                 "kind": "reviewed-interrupted-run-recovery" if recovered else "completed-generation-and-native-replay"},
                  "evidenceSha256": digest(evidence_bytes)}
        # The completion marker is written last; only a complete entry is moved
        # into the content-addressed namespace. A killed publisher is a miss.
        (staging / "complete.json").write_bytes(encoded(marker))
        check_entry(staging, expected)
        os.rename(staging, destination)
        print(f"Published complete public fixture cache: {key}")
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("key", "restore", "publish"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--generation-commit")
    parser.add_argument("--reviewed-recovery", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.operation == "key":
        print(context(root)[0])
    elif args.operation == "restore":
        return 0 if restore(root, args.cache) else 3
    else:
        if not args.evidence or not args.generation_commit:
            parser.error("publish requires evidence and generation commit")
        publish(root, args.cache, (args.source or root).resolve(), args.evidence,
                args.generation_commit, args.reviewed_recovery)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise SystemExit(f"Public proof fixture cache refused: {error}")
