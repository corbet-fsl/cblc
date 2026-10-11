#!/usr/bin/env python3
"""Retain or check the actual native test worker; never execute a cached worker."""
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


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def identity(name, size):
    value = os.environ[name]
    if re.fullmatch(f"[0-9a-f]{{{size}}}", value) is None:
        raise ValueError(f"Invalid {name} identity")
    return value


def elf(path, tool):
    def read(flag):
        return subprocess.check_output([tool, flag, str(path)], text=True)

    header = read("-h")
    fields = {}
    for name in ("Class", "Data", "Machine"):
        fields[name] = re.search(rf"^\s*{name}:\s*(.+)$", header, re.M)[1]
    dynamic = read("-d")
    needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)
    runpaths = []
    for value in re.findall(r"\((?:RUNPATH|RPATH)\).*\[([^\]]+)\]", dynamic):
        runpaths.extend(value.split(":"))
    interpreter = re.search(r"Requesting program interpreter:\s*([^\]]+)\]", read("-l"))
    return fields, needed, runpaths, Path(interpreter[1]) if interpreter else None


def runtime(worker):
    tool = shutil.which("readelf") or shutil.which("llvm-readelf")
    if not tool:
        raise RuntimeError("An existing ELF inspection tool is required")
    fields, needed, search, interpreter = elf(worker, tool)
    if interpreter is None or not interpreter.is_file():
        raise RuntimeError("The actual native interpreter is unavailable")
    paths = {interpreter.resolve()}
    search.append(str(interpreter.parent))
    unresolved = set(needed)
    inspected = set()
    # Inspect the existing transitive library search paths too. An unused absent
    # search slot supplies no runtime file; it is recorded, never provisioned.
    while unresolved:
        progress = False
        for name in sorted(unresolved):
            if "/" in name:
                raise ValueError("Unexpected native library name")
            candidates = [Path(directory) / name for directory in search]
            found = next((path.resolve() for path in candidates if path.is_file()), None)
            if found is None:
                continue
            unresolved.remove(name)
            progress = True
            if found not in inspected:
                inspected.add(found)
                paths.add(found)
                _, child_needed, child_search, _ = elf(found, tool)
                unresolved.update(set(child_needed) - {path.name for path in paths})
                search.extend(path for path in child_search if path not in search)
            if len(paths) > 32:
                raise ValueError("Native runtime closure exceeds its test-artifact bound")
        if not progress:
            raise RuntimeError(f"Unresolved existing runtime libraries: {sorted(unresolved)}")
    return {"elf": fields, "interpreter": str(interpreter), "runpaths": search,
            "files": [{"path": str(path), "sha256": digest(path)} for path in sorted(paths)]}


def export(worker, output):
    worker = worker.resolve(strict=True)
    info = worker.stat()
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise ValueError("The current built worker must be a regular executable")
    source = identity("CI_COMMIT_SHA", 40)
    archive = identity("SOURCE_SHA256", 64)
    metadata = {"version": 1, "sourceCommit": source, "sourceArchiveSha256": archive,
                "cargoLockSha256": digest(Path("Cargo.lock")),
                "nativeSdkSha256": digest(Path(".ci/native-sdk.json")),
                "compiler": subprocess.check_output(["rustc", "-vV"], text=True),
                "platform": {"system": platform.system(), "machine": platform.machine()},
                "runtime": runtime(worker), "workerSha256": digest(worker),
                "workerBytes": info.st_size, "workerMode": stat.S_IMODE(info.st_mode)}
    output.mkdir(parents=True, exist_ok=True)
    target = output / "worker"
    shutil.copy2(worker, target)
    if digest(target) != metadata["workerSha256"]:
        raise ValueError("Worker changed during artifact capture")
    (output / "worker.json").write_text(json.dumps(metadata, sort_keys=True) + "\n")
    print(json.dumps({"sourceCommit": source, "workerSha256": metadata["workerSha256"],
                      "metadataSha256": digest(output / "worker.json")}))


def check(directory, expected_source, expected_metadata, output):
    metadata_path = directory / "worker.json"
    with metadata_path.open("rb") as source:
        metadata_bytes = source.read(65537)
    if len(metadata_bytes) > 65536 or hashlib.sha256(metadata_bytes).hexdigest() != expected_metadata:
        raise ValueError("Worker metadata differs from the independently pinned capture")
    metadata = json.loads(metadata_bytes)
    if metadata["version"] != 1 or metadata["sourceCommit"] != expected_source:
        raise ValueError("Worker source identity is unavailable or mismatched")
    if metadata["platform"] != {"system": platform.system(), "machine": platform.machine()}:
        raise ValueError("Native worker platform is incompatible")
    worker = directory / "worker"
    info = worker.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != metadata["workerMode"]:
        raise ValueError("Worker executable metadata differs")
    if info.st_size != metadata["workerBytes"] or digest(worker) != metadata["workerSha256"]:
        raise ValueError("Worker bytes differ from the independently pinned capture")
    if not Path(metadata["runtime"]["interpreter"]).is_file():
        raise ValueError("Native interpreter is unavailable")
    for item in metadata["runtime"]["files"]:
        path = Path(item["path"])
        if not path.is_file() or digest(path) != item["sha256"]:
            raise ValueError("Required native runtime bytes are unavailable or mismatched")
    fixture = json.loads((directory / "gather-record-fixture.json").read_text())
    if fixture["fixtureSource"] != expected_source:
        raise ValueError("Proof fixture and worker source identities differ")
    limits = {"gather-record-fixture.json": 1024 * 1024, "config.json": 65536,
              "manifest.json": 65536, "circuits.json": 64 * 1024 * 1024,
              "keys.json": 1024 * 1024, "setup/g1.dat": 128 * 1024 * 1024,
              "setup/g2.dat": 1024}
    if set(metadata["artifactFiles"]) != set(limits):
        raise ValueError("Unexpected native fixture artifact list")
    # Each job takes its own verified snapshot. A later producer cannot change
    # the cached binary or proof inputs between validation and native execution.
    output.mkdir(parents=True, exist_ok=False)
    target = output / "worker"
    shutil.copy2(worker, target)
    copied = target.stat()
    if (not stat.S_ISREG(copied.st_mode) or stat.S_IMODE(copied.st_mode) != metadata["workerMode"]
            or copied.st_size != metadata["workerBytes"] or digest(target) != metadata["workerSha256"]):
        raise ValueError("Worker changed during the consuming snapshot")
    for name, maximum in limits.items():
        source = directory / name
        if source.stat().st_size > maximum:
            raise ValueError("Fixture artifact exceeds its existing input bound")
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if digest(target) != metadata["artifactFiles"][name]:
            raise ValueError("Fixture artifact differs from the pinned capture")
    print((output / "worker").resolve())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("export")
    capture.add_argument("--worker", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    validate = sub.add_parser("check")
    validate.add_argument("--directory", type=Path, required=True)
    validate.add_argument("--source", required=True)
    validate.add_argument("--metadata-sha256", required=True)
    validate.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.command == "export":
        export(arguments.worker, arguments.output)
    else:
        check(arguments.directory, arguments.source, arguments.metadata_sha256, arguments.output)
