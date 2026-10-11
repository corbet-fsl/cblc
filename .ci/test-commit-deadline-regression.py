#!/usr/bin/env python3
"""Require real named libtest assertions when atomic deadline guards are weakened."""
import os
from pathlib import Path
import re
import subprocess


CONTROLS = (
    (
        "src/storage.rs",
        "storage::tests::live_commit_deadline_refuses_expiry_and_clock_rollback_before_memory_swap",
        "tests/internal/storage.rs",
        b"if now >= self.expires_at {",
        b"if now > self.expires_at {",
        "exclusive expiry",
    ),
    (
        "src/storage.rs",
        "storage::tests::return_clock_cannot_move_behind_the_atomic_decision_observation",
        "tests/internal/storage.rs",
        b"self.observed.set(now);",
        b"self.observed.set(self.observed.get());",
        "highest observed time",
    ),
    (
        "src/storage.rs",
        "storage::tests::late_successful_commit_reports_reconciliation_and_keeps_committed_state",
        "tests/internal/storage.rs",
        b"self.0.commit_before(deadline)?;\n        deadline.check().map_err(|_| Error::Storage)?;",
        b"self.0.commit_before(deadline)?;",
        "fresh return check",
    ),
    (
        "src/storage.rs",
        "storage::tests::live_commit_deadline_refuses_expiry_and_clock_rollback_before_memory_swap",
        "tests/internal/storage.rs",
        b"now.to_string().into_bytes()",
        b"{ let _ = now; b\"0\".to_vec() }",
        "persisted logical commit observation",
    ),
    (
        "src/accounting_ledger.rs",
        "accounting_ledger::clock_tests::observations_survive_new_calls_and_invalid_samples_cannot_lower_or_poison_them",
        "tests/internal/ledger_clock.rs",
        b"observed.fetch_max(now, Ordering::AcqRel)",
        b"observed.load(Ordering::Acquire)",
        "observations retained across calls",
    ),
    (
        "src/accounting_ledger.rs",
        "accounting_ledger::clock_tests::ledger_clock_numeric_bounds_and_floor_are_checked",
        "tests/internal/ledger_clock.rs",
        b"if now == 0 || now < floor || now > MAX_INTEGER {",
        b"if now == 0 || now < floor {",
        "bounded ledger clock integer",
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


def require_assertion(test, label, test_source="tests/internal/storage.rs"):
    status, output = run(test)
    # A build failure, zero selected tests, panic in a dependency or unrelated
    # failing test is not evidence that the deadline assertion detects a defect.
    if (status != 101 or not named_result(output, test, "FAILED")
            or "test result: FAILED. 0 passed; 1 failed; 0 ignored;" not in output
            or not re.search(r"thread '" + re.escape(test)
                             + r"'(?: \([0-9]+\))? panicked at (?:src/\.\./)?"
                             + re.escape(test_source) + r":[0-9]+:[0-9]+:",
                             output)
            or "assertion `left == right` failed" not in output
            or "error[E" in output or "could not compile" in output):
        print(output)
        raise SystemExit(f"Weakened {label} did not fail its exact regression assertion")
    print(f"Atomic deadline control rejected by regression assertion ({label}): {test}")


def main():
    originals = {Path(source): Path(source).read_bytes()
                 for source, *_ in CONTROLS}
    try:
        for source, test, test_source, before, after, label in CONTROLS:
            path = Path(source)
            original = originals[path]
            if original.count(before) != 1:
                raise SystemExit(f"Atomic deadline control source drift: {label}")
            require_baseline(test)
            path.write_bytes(original.replace(before, after))
            try:
                require_assertion(test, label, test_source)
            finally:
                path.write_bytes(original)
    finally:
        for path, original in originals.items():
            path.write_bytes(original)
    for path, original in originals.items():
        if path.read_bytes() != original:
            raise SystemExit(f"Atomic deadline source restoration failed: {path}")


if __name__ == "__main__":
    main()
