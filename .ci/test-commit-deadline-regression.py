#!/usr/bin/env python3
"""Require real named libtest assertions when atomic deadline guards are weakened."""
import os
from pathlib import Path
import re
import subprocess


SOURCE = Path("src/storage.rs")
CONTROLS = (
    (
        "live_commit_deadline_refuses_expiry_and_clock_rollback_before_memory_swap",
        b"if now >= self.expires_at {",
        b"if now > self.expires_at {",
        "exclusive expiry",
    ),
    (
        "return_clock_cannot_move_behind_the_atomic_decision_observation",
        b"self.observed.set(now);",
        b"self.observed.set(self.observed.get());",
        "highest observed time",
    ),
    (
        "late_successful_commit_is_expired_fresh_authority_and_keeps_committed_state",
        b"self.0.commit_before(deadline)?;\n        deadline.check()?;",
        b"self.0.commit_before(deadline)?;",
        "fresh return check",
    ),
)


def run(test):
    result = subprocess.run(
        ["cargo", "test", "--locked", "--all-features", "--lib", test,
         "--", "--exact", "--nocapture"],
        capture_output=True,
        text=True,
        timeout=900,
        env={**os.environ, "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"},
    )
    return result.returncode, result.stdout + result.stderr


def named_result(output, test, result):
    return re.search(r"^test " + re.escape(test) + r" \.\.\. " + result + r"$",
                     output, re.M) is not None


def require_baseline(test):
    status, output = run(test)
    if (status != 0 or not named_result(output, test, "ok")
            or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in output):
        print(output)
        raise SystemExit(f"Deadline control needs a passing exact baseline: {test}")


def require_assertion(test, label):
    status, output = run(test)
    # A build failure, zero selected tests, panic in a dependency or unrelated
    # failing test is not evidence that the deadline assertion detects a defect.
    if (status != 101 or not named_result(output, test, "FAILED")
            or "test result: FAILED. 0 passed; 1 failed; 0 ignored;" not in output
            or not re.search(r"thread '" + re.escape(test)
                             + r"'(?: \([0-9]+\))? panicked at (?:src/\.\./)?tests/internal/storage\.rs:[0-9]+:[0-9]+:",
                             output)
            or "assertion `left == right` failed" not in output
            or "error[E" in output or "could not compile" in output):
        print(output)
        raise SystemExit(f"Weakened {label} did not fail its exact regression assertion")
    print(f"Atomic deadline control rejected by regression assertion ({label}): {test}")


def main():
    original = SOURCE.read_bytes()
    try:
        for name, before, after, label in CONTROLS:
            if original.count(before) != 1:
                raise SystemExit(f"Atomic deadline control source drift: {label}")
            test = f"storage::tests::{name}"
            require_baseline(test)
            SOURCE.write_bytes(original.replace(before, after))
            try:
                require_assertion(test, label)
            finally:
                SOURCE.write_bytes(original)
    finally:
        SOURCE.write_bytes(original)
    if SOURCE.read_bytes() != original:
        raise SystemExit("Atomic deadline source restoration failed")


if __name__ == "__main__":
    main()
