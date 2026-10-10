#!/usr/bin/env python3
"""Exercise cache integrity with tiny dummy bytes, never accepting fake proofs."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("proof_cache", Path(__file__).with_name("proof-cache.py"))
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


class ProofCache(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        paths = ["Cargo.toml", "Cargo.lock", "package.json", "package-lock.json", "src/lib.rs", "tests/helper.rs", *cache.IMPLEMENTATION]
        for name in paths:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture input {name}\n")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture inputs")
        self.commit = self.git("rev-parse", "HEAD").strip()
        self.store = self.base / "cache"
        for directory in cache.DIRECTORIES:
            fixture = self.root / directory
            (fixture / "setup").mkdir(parents=True)
            setup = b"fictional setup bytes"
            (fixture / "setup/g1.dat").write_bytes(setup)
            manifest = {"setup": [{"name": "g1.dat", "bytes": len(setup), "sha256": cache.digest(setup)}]}
            self.write_json(fixture / "manifest.json", manifest)
            self.write_json(fixture / "config.json", {"directory": str(fixture), "manifestSha256": cache.digest((fixture / "manifest.json").read_bytes())})
        account = self.root / ".proof-test"
        for name in ("circuit.json", "vk.bin"):
            (account / name).write_text("dummy")
        self.write_json(account / "records.json", [{}, {}])
        self.write_json(account / "ledger-records.json", [{}] * 6)
        extension = self.root / ".extension-test"
        for name in ("circuits.json", "keys.json"):
            (extension / name).write_text("dummy")
        self.write_json(extension / "results.json", {"checks": ["dummy integrity fixture"]})
        self.write_json(extension / "public-trace.json", [{}] * 66)
        (extension / "source.txt").write_text(f"{self.commit}\n{cache.digest((self.root / 'package-lock.json').read_bytes())}  package-lock.json\n")
        self.evidence = self.base / "generation.log"
        self.evidence.write_text(self.commit + "\n" + "\n".join(cache.MARKERS))
        self.key, self.expected = cache.context(self.root)
        self.entry = self.store / self.key

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True, stderr=subprocess.DEVNULL)

    @staticmethod
    def write_json(path, value):
        path.write_bytes(cache.encoded(value))

    def publish(self):
        cache.publish(self.root, self.store, self.root, self.evidence, self.commit, False)

    def check(self):
        return cache.check_entry(self.entry, self.expected)

    def test_restore_relocates_only_copied_configuration_and_keeps_original_bytes(self):
        self.publish()
        original = (self.entry / "payload/.proof-test/config.json").read_bytes()
        target = self.base / "different-workspace"
        shutil.copytree(self.root, target, ignore=shutil.ignore_patterns(*cache.DIRECTORIES))
        self.assertTrue(cache.restore(target, self.store))
        self.assertEqual(json.loads((target / ".proof-test/config.json").read_text())["directory"], str(target / ".proof-test"))
        self.assertEqual(original, (self.entry / "payload/.proof-test/config.json").read_bytes())
        self.assertEqual(cache.inventory(target / ".extension-test")[0]["path"], "circuits.json")
        self.check()
        with self.assertRaisesRegex(ValueError, "fresh"):
            cache.restore(target, self.store)

    def test_source_code_and_helper_changes_invalidate_key_but_top_level_docs_do_not(self):
        self.publish()
        (self.root / "README.md").write_text("Documentation only")
        self.git("add", "README.md")
        self.assertEqual(cache.context(self.root)[0], self.key)
        for name in ("src/lib.rs", "tests/helper.rs", "Cargo.lock", "package-lock.json", *cache.IMPLEMENTATION):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            new_key, changed = cache.context(self.root)
            self.assertNotEqual(new_key, self.key)
            with self.assertRaisesRegex(ValueError, "input mismatch"):
                cache.check_entry(self.entry, changed)
            self.assertFalse(cache.restore(self.root, self.store))
            path.write_bytes(original)

    def test_missing_and_partial_entries_never_restore(self):
        self.assertFalse(cache.restore(self.root, self.store))
        self.publish()
        (self.entry / "complete.json").unlink()
        with self.assertRaisesRegex(ValueError, "Partial"):
            cache.restore(self.root, self.store)

    def test_altered_bytes_and_unexpected_payload_files_are_refused(self):
        self.publish()
        proof = self.entry / "payload/.proof-test/vk.bin"
        proof.write_text("altered")
        with self.assertRaisesRegex(ValueError, "content mismatch"):
            self.check()

    def test_unexpected_top_level_file_is_refused(self):
        self.publish()
        (self.entry / "unexpected").write_text("extra")
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.check()

    def test_unexpected_payload_files_and_empty_directories_are_refused_even_with_updated_inventory(self):
        self.publish()
        for name, is_directory in (("witness.json", False), ("extra", True)):
            path = self.entry / "payload/.proof-test" / name
            path.mkdir() if is_directory else path.write_text("must never be cached")
            marker = json.loads((self.entry / "complete.json").read_text())
            marker["files"] = cache.inventory(self.entry / "payload")
            self.write_json(self.entry / "complete.json", marker)
            with self.assertRaisesRegex(ValueError, "Unrecognized"):
                self.check()
            path.rmdir() if is_directory else path.unlink()

    def test_file_and_directory_symlinks_are_refused(self):
        self.publish()
        for name, target in (("link", self.evidence), ("directory-link", self.root)):
            path = self.entry / "payload/.proof-test" / name
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                self.check()
            path.unlink()

    def test_truncated_generation_and_missing_evidence_cannot_publish(self):
        trace = self.root / ".extension-test/public-trace.json"
        trace.unlink()
        with self.assertRaises(OSError):
            self.publish()
        self.assertFalse(self.entry.exists())
        self.write_json(trace, [{}] * 66)
        self.evidence.write_text("generation started")
        with self.assertRaisesRegex(ValueError, "Missing completed"):
            self.publish()
        self.assertFalse(self.entry.exists())

    def test_input_commit_and_lock_provenance_must_match(self):
        with self.assertRaisesRegex(ValueError, "commit mismatch"):
            cache.publish(self.root, self.store, self.root, self.evidence, "0" * 40, True)
        (self.root / ".extension-test/source.txt").write_text("inconsistent provenance")
        with self.assertRaisesRegex(ValueError, "provenance mismatch"):
            self.publish()
        self.assertFalse(self.entry.exists())

    def test_recovery_checks_exact_fixture_inputs_and_records_new_cache_machinery(self):
        old = self.base / "old-generation"
        shutil.copytree(self.root, old)
        (self.root / ".ci/proof-cache.py").write_text("reviewed new cache mechanism")
        cache.publish(self.root, self.store, old, self.evidence, self.commit, True)
        key, current = cache.context(self.root)
        marker = cache.check_entry(self.store / key, current)
        self.assertEqual(marker["provenance"]["kind"], "reviewed-interrupted-run-recovery")
        (old / "src/lib.rs").write_text("different artifact-producing source")
        with self.assertRaisesRegex(ValueError, "inputs differ"):
            cache.publish(self.root, self.store, old, self.evidence, self.commit, True)

    def test_evidence_tamper_and_partial_marker_are_refused(self):
        self.publish()
        evidence = self.entry / "evidence.log"
        original = evidence.read_bytes()
        evidence.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "evidence mismatch"):
            self.check()
        evidence.write_bytes(original)
        marker = json.loads((self.entry / "complete.json").read_text())
        del marker["provenance"]
        self.write_json(self.entry / "complete.json", marker)
        with self.assertRaisesRegex(ValueError, "completion marker"):
            self.check()

    def test_only_derived_publication_is_discarded_and_incomplete_cache_is_never_selected(self):
        (self.root / ".extension-test/publication.json").write_text("derived by current adversary executable")
        self.publish()
        self.assertFalse((self.entry / "payload/.extension-test/publication.json").exists())
        self.check()
        self.publish()  # Identical completed entry is immutable and idempotent.

    def test_setup_hash_and_path_are_checked(self):
        manifest = self.root / ".proof-test/manifest.json"
        value = json.loads(manifest.read_text())
        value["setup"][0]["name"] = ".."
        self.write_json(manifest, value)
        config = self.root / ".proof-test/config.json"
        self.write_json(config, {"directory": "old", "manifestSha256": cache.digest(manifest.read_bytes())})
        with self.assertRaisesRegex(ValueError, "setup filename"):
            self.publish()


if __name__ == "__main__":
    unittest.main()
