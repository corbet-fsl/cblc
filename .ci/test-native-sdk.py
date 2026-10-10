#!/usr/bin/env python3
"""The ABI guard must reject unreviewed dependency/artifact combinations."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("native_sdk", Path(__file__).with_name("check-native-sdk.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativeSdkTests(unittest.TestCase):
    def test_matching(self):
        module.check({"package": [{"name": "barretenberg-rs", "version": "5.2.1"}]},
                     {"version": "5.2.1", "sha256": "ab" * 32})

    def test_missing_duplicate_or_different_sdk(self):
        for versions in [[], ["5.2.0"], ["5.2.1", "5.2.1"], ["5.2.1", "5.3.0"]]:
            with self.subTest(versions=versions), self.assertRaises(ValueError):
                module.check({"package": [{"name": "barretenberg-rs", "version": v} for v in versions]},
                             {"version": "5.2.1", "sha256": "ab" * 32})

    def test_invalid_artifact_identity(self):
        for version, digest in [(None, "ab" * 32), ("5", "ab" * 32), ("5.2.1", ""), ("5.2.1", "AB" * 32)]:
            with self.subTest(version=version, digest=digest), self.assertRaises(ValueError):
                module.check({"package": [{"name": "barretenberg-rs", "version": "5.2.1"}]},
                             {"version": version, "sha256": digest})


if __name__ == "__main__":
    unittest.main()
