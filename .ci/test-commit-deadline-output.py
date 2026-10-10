#!/usr/bin/env python3
"""Keep mutation evidence strict across supported Rust panic-header formats."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch


DIRECTORY = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "deadline_control", DIRECTORY / "test-commit-deadline-regression.py")
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
NAME = "storage::tests::live_commit_deadline_refuses_expiry_and_clock_rollback_before_memory_swap"
# Captured libtest output from the real exclusive-expiry mutation. Build output
# is omitted; it contains no evidence required to identify the failed assertion.
CAPTURED = (DIRECTORY / "fixtures/commit-deadline-panic.txt").read_text()


class DeadlineOutputTests(unittest.TestCase):
    def check_output(self, status, output):
        with patch.object(control, "run", return_value=(status, output)), \
                contextlib.redirect_stdout(io.StringIO()):
            control.require_assertion(NAME, "output parser fixture")

    def test_captured_assertion_with_numeric_process_id(self):
        self.check_output(101, CAPTURED)

    def test_panic_headers_without_process_id_or_relative_parent(self):
        for output in [CAPTURED.replace(" (399243)", ""),
                       CAPTURED.replace("src/../tests/", "tests/")]:
            with self.subTest(output=output):
                self.check_output(101, output)

    def test_non_assertion_failures_and_wrong_selection_are_rejected(self):
        cases = [
            (1, CAPTURED),
            (0, CAPTURED),
            (101, CAPTURED.replace(NAME, "unrelated::test")),
            (101, CAPTURED.replace("1 failed", "0 failed")),
            (101, CAPTURED.replace("0 passed", "1 passed")),
            (101, CAPTURED.replace("0 ignored", "1 ignored")),
            (101, CAPTURED.replace("assertion `left == right` failed", "upstream panic")),
            (101, CAPTURED.replace("tests/internal/storage.rs", "dependency/other.rs")),
            (101, CAPTURED.replace(" (399243)", " (not-a-process-id)")),
            (101, CAPTURED + "error[E0425]: cannot find value\n"),
            (101, CAPTURED + "error: could not compile cblc\n"),
            (101, "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;\n"),
        ]
        for status, output in cases:
            with self.subTest(status=status, output=output), self.assertRaises(SystemExit):
                self.check_output(status, output)


if __name__ == "__main__":
    unittest.main()
