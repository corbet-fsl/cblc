#!/usr/bin/env python3
"""Require the real activation fixture to detect removal of the scope guard."""
import os
from pathlib import Path
import re
import subprocess

SOURCE = Path("src/accounting_ledger/extensions.rs")
GUARD = b"if scope == self.proof_scope {\n            return Err(Error::PolicyMismatch);\n        }"
MARKER = "Equal account and extension scopes refused activation"
ASSERTION = "equal account and extension scopes must refuse activation"


def run():
    result = subprocess.run(
        ["cargo", "run", "--locked", "--all-features", "--example",
         "extension_adversaries", "--", "--equal-scope-only"],
        capture_output=True, text=True, timeout=900,
        env={**os.environ, "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"},
    )
    return result.returncode, result.stdout + result.stderr


def main():
    original = SOURCE.read_bytes()
    if original.count(GUARD) != 1:
        raise SystemExit("Extension scope control source drift")
    status, output = run()
    if status != 0 or MARKER not in output:
        print(output)
        raise SystemExit("Extension scope control needs a passing real baseline")
    try:
        SOURCE.write_bytes(original.replace(GUARD, b""))
        status, output = run()
        # Compilation failures or unrelated fixture panics cannot satisfy this
        # control: the exact equal-scope assertion must reject real activation.
        if (status != 101 or ASSERTION not in output or MARKER in output
                or not re.search(r"thread 'main'(?: \([0-9]+\))? panicked at "
                                 r"examples/extension_adversaries\.rs:[0-9]+:[0-9]+:", output)
                or "error[E" in output or "could not compile" in output):
            print(output)
            raise SystemExit("Removed scope guard did not fail its regression assertion")
        print("Removed extension scope guard rejected by real activation assertion")
    finally:
        SOURCE.write_bytes(original)
    if SOURCE.read_bytes() != original:
        raise SystemExit("Extension scope source restoration failed")


if __name__ == "__main__":
    main()
