import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import audit_upstreams as audit


def make_source(source_id="alpha", mode="monitor", mirror_path=None, approved=False):
    return {
        "id": source_id,
        "url": "https://raw.githubusercontent.com/example/rules/master/rule/Surge/Test/Test.list",
        "mode": mode,
        "license": "GPL-2.0",
        "license_url": "https://github.com/example/rules/blob/master/LICENSE",
        "redistribution_approved": approved,
        "mirror_path": mirror_path,
    }


def make_state_entry(source_id="alpha", mode="monitor", mirror_path=None, data=b"DOMAIN,example.com\n"):
    return {
        "id": source_id,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "lines": 1,
        "mode": mode,
        "mirror_path": mirror_path,
    }


class ValidateSourceTests(unittest.TestCase):
    def test_accepts_https_raw_github_monitor_source(self):
        audit.validate_source(make_source())

    def test_rejects_non_raw_github_host(self):
        source = make_source()
        source["url"] = "https://example.com/rules/Test.list"
        with self.assertRaises(ValueError):
            audit.validate_source(source)

    def test_mirror_requires_explicit_approval_and_license(self):
        source = make_source(mode="mirror", mirror_path="upstream/example.list")
        with self.assertRaises(ValueError):
            audit.validate_source(source)
        source["redistribution_approved"] = True
        source["license"] = "UNVERIFIED"
        with self.assertRaises(ValueError):
            audit.validate_source(source)

    def test_rejects_mirror_path_traversal(self):
        source = make_source(mode="mirror", mirror_path="upstream/../outside.list", approved=True)
        with self.assertRaises(ValueError):
            audit.validate_source(source)

    def test_rejects_mirror_path_through_symlink(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            (root / "upstream").symlink_to(outside, target_is_directory=True)
            source = make_source(mode="mirror", mirror_path="upstream/example.list", approved=True)
            with mock.patch.object(audit, "ROOT", root):
                with self.assertRaises(ValueError):
                    audit.validate_source(source)


class ValidateRulesTests(unittest.TestCase):
    def test_strict_rule_validation_accepts_known_rule(self):
        self.assertEqual(audit.validate_rules("DOMAIN,example.com\n", "test", strict=True), 1)

    def test_rejects_html_and_unknown_strict_rule(self):
        with self.assertRaises(ValueError):
            audit.validate_rules("<!doctype html><html></html>", "test")
        with self.assertRaises(ValueError):
            audit.validate_rules("UNKNOWN,example.com\n", "test", strict=True)


class ValidateStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state_path = self.root / "upstreams" / "state.json"
        self.state_path.parent.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def write_state(self, entries):
        self.state_path.write_text(
            json.dumps({"schema": 1, "sources": entries}), encoding="utf-8"
        )

    def validate(self, sources, for_sync=False):
        with mock.patch.object(audit, "ROOT", self.root), mock.patch.object(audit, "STATE", self.state_path):
            return audit.validate_state(sources, for_sync=for_sync)

    def test_sync_allows_new_catalog_entries_but_offline_check_does_not(self):
        self.write_state([make_state_entry()])
        sources = [make_source(), make_source("beta")]
        self.assertIn("alpha", self.validate(sources, for_sync=True))
        with self.assertRaisesRegex(ValueError, "State/catalog source list mismatch"):
            self.validate(sources)

    def test_sync_rejects_implicit_source_removal(self):
        self.write_state([make_state_entry()])
        with self.assertRaisesRegex(ValueError, "explicit reviewed state cleanup"):
            self.validate([], for_sync=True)

    def test_sync_can_bootstrap_newly_approved_mirror(self):
        self.write_state([make_state_entry(mode="monitor")])
        source = make_source(mode="mirror", mirror_path="upstream/alpha.list", approved=True)
        self.validate([source], for_sync=True)
        with self.assertRaisesRegex(ValueError, "Missing mirror file"):
            self.validate([source])

    def test_sync_refuses_to_overwrite_untracked_mirror_file(self):
        self.write_state([make_state_entry(mode="monitor")])
        path = self.root / "upstream" / "alpha.list"
        path.parent.mkdir()
        path.write_text("locally managed data", encoding="utf-8")
        source = make_source(mode="mirror", mirror_path="upstream/alpha.list", approved=True)
        with self.assertRaisesRegex(ValueError, "untracked mirror file"):
            self.validate([source], for_sync=True)

    def test_existing_mirror_must_match_recorded_digest(self):
        data = b"DOMAIN,example.com\n"
        self.write_state([make_state_entry(mode="mirror", mirror_path="upstream/alpha.list", data=data)])
        path = self.root / "upstream" / "alpha.list"
        path.parent.mkdir()
        path.write_bytes(data)
        source = make_source(mode="mirror", mirror_path="upstream/alpha.list", approved=True)
        self.validate([source])
        path.write_bytes(b"DOMAIN,changed.example\n")
        with self.assertRaisesRegex(ValueError, "Mirror and approved state differ"):
            self.validate([source], for_sync=True)

    def test_existing_mirror_path_cannot_change_silently(self):
        self.write_state([make_state_entry(mode="mirror", mirror_path="upstream/old.list")])
        source = make_source(mode="mirror", mirror_path="upstream/new.list", approved=True)
        with self.assertRaisesRegex(ValueError, "Changing an existing mirror path"):
            self.validate([source], for_sync=True)


if __name__ == "__main__":
    unittest.main()
