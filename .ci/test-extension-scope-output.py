#!/usr/bin/env python3
"""Inert tests of scope-mutation failure evidence and source restoration."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "scope_control", Path(__file__).with_name("test-extension-scope-regression.py")
)
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


class Evidence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "extensions.rs"
        self.original = b"before\n" + control.GUARD + b"\nafter\n"
        self.source.write_bytes(self.original)
        self.valid = ("thread 'main' (123) panicked at "
                      "examples/extension_adversaries.rs:166:5:\n" + control.ASSERTION)

    def invoke(self, results):
        with patch.object(control, "SOURCE", self.source), \
                patch.object(control, "run", side_effect=results) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                control.main()
            finally:
                self.assertEqual(self.source.read_bytes(), self.original)
            return run.call_count

    def test_exact_regression_panic_is_accepted_and_original_bytes_are_restored(self):
        for output in [self.valid, self.valid.replace(" (123)", "")]:
            with self.subTest(output=output):
                self.assertEqual(self.invoke([(0, control.MARKER), (101, output)]), 2)

    def test_failed_baseline_or_missing_completion_marker_cannot_start_control(self):
        for baseline in [(101, self.valid), (0, ""), (1, control.MARKER)]:
            with self.subTest(baseline=baseline), self.assertRaises(SystemExit):
                self.invoke([baseline])

    def test_compiler_errors_and_unrelated_failures_cannot_satisfy_control(self):
        outcomes = [
            (0, self.valid),
            (101, "could not compile\n" + self.valid),
            (101, "error[E0308]\n" + self.valid),
            (101, control.ASSERTION),
            (101, self.valid.replace("examples/extension_adversaries.rs", "other.rs")),
            (101, self.valid.replace(control.ASSERTION, "unrelated assertion")),
            (101, self.valid + "\n" + control.MARKER),
        ]
        for outcome in outcomes:
            with self.subTest(outcome=outcome), self.assertRaises(SystemExit):
                self.invoke([(0, control.MARKER), outcome])

    def test_execution_exception_also_restores_source_bytes(self):
        with self.assertRaisesRegex(RuntimeError, "worker interrupted"):
            self.invoke([(0, control.MARKER), RuntimeError("worker interrupted")])

    def test_missing_or_duplicate_guard_refuses_before_cargo_invocation(self):
        for contents in [b"no guard", control.GUARD * 2]:
            self.original = contents
            self.source.write_bytes(contents)
            with self.subTest(contents=contents), self.assertRaises(SystemExit):
                self.invoke([])


if __name__ == "__main__":
    unittest.main()
