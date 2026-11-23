"""Offline regression tests for eight curated GPL-2.0 service rule-sets."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts import build_service_rules as mod

NAMES = [
    ("google", "Google"), ("youtube", "YouTube"), ("apple_all", "Apple"),
    ("openai", "OpenAI"), ("telegram", "Telegram"),
    ("netflix", "Netflix"), ("spotify", "Spotify"), ("hbo", "HBO"),
]


class ManagedServicesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for folder in ("config", "upstreams", "sources/blackmatrix7", "upstream/blackmatrix7", "rules"):
            (self.root / folder).mkdir(parents=True, exist_ok=True)
        (self.root / mod.LICENSE).write_text("GPL-2.0 test license", encoding="utf-8")
        self.manifest = {
            "schema": 1, "license": "GPL-2.0",
            "license_file": mod.LICENSE.as_posix(),
            "source_repo": mod.SOURCE_REPO,
            "services": []
        }
        self.catalog = {"schema": 1, "sources": []}
        self.state = {"schema": 1, "sources": []}
        for alias, name in NAMES:
            sid = "blackmatrix7-" + alias
            mirror = f"upstream/blackmatrix7/{name}.list"
            published = f"rules/{name}.list"
            data = b"DOMAIN,example.org\nOR,((IP-ASN,44907,no-resolve),(IP-ASN,59930,no-resolve))\n"
            (self.root / mirror).write_bytes(data)
            self.manifest["services"].append({
                "id": sid, "name": name, "mirror_path": mirror,
                "published_path": published, "baseline_rules": 2
            })
            self.catalog["sources"].append({
                "id": sid, "url": f"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/{name}/{name}.list",
                "mode": "mirror", "redistribution_approved": True,
                "license": "GPL-2.0", "license_url": mod.SOURCE_REPO + "/blob/master/LICENSE",
                "mirror_path": mirror
            })
            self.state["sources"].append({
                "id": sid, "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data), "lines": 2, "mode": "mirror",
                "mirror_path": mirror
            })
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        for path, obj in (
            (mod.MANIFEST, self.manifest),
            (mod.CATALOG, self.catalog),
            (mod.STATE, self.state),
        ):
            (self.root / path).write_text(json.dumps(obj) + "\n", encoding="utf-8")

    def test_generation_preserves_all_predicates_and_complex_or(self):
        result = mod.build_outputs(self.root)
        self.assertEqual(len(result), 8)
        self.assertIn("rules/HBO.list", result)
        raw = (self.root / "upstream/blackmatrix7/Telegram.list").read_bytes()
        output = result["rules/Telegram.list"]
        self.assertTrue(output.endswith(raw))
        self.assertIn(b"OR,((IP-ASN,44907,no-resolve)", output)
        self.assertIn(b"# Local change 2026-11-23:", output)

    def test_real_hbo_rules_preserved_verbatim(self):
        output = mod.build_outputs(mod.ROOT)["rules/HBO.list"]
        original = (mod.ROOT / "upstream/blackmatrix7/HBO.list").read_bytes()
        self.assertEqual(len(mod.source_rules(original, "HBO")), 50)
        self.assertTrue(output.endswith(original))
        self.assertIn(b"DOMAIN-SUFFIX,max.com", output)

    def test_rejects_tampered_snapshot(self):
        path = self.root / "upstream/blackmatrix7/Google.list"
        path.write_bytes(b"DOMAIN,malicious.org\n")
        with self.assertRaisesRegex(ValueError, "Snapshot differs"):
            mod.build_outputs(self.root)

    def test_rejects_unapproved_mirroring(self):
        self.catalog["sources"][0]["redistribution_approved"] = False
        self.save()
        with self.assertRaisesRegex(ValueError, "Unapproved"):
            mod.build_outputs(self.root)

    def test_rejects_unreviewed_rule_type(self):
        path = self.root / "upstream/blackmatrix7/Google.list"
        raw = b"RULE-SET,https://example.org/other.list\n"
        path.write_bytes(raw)
        rec = self.state["sources"][0]
        rec["sha256"] = hashlib.sha256(raw).hexdigest()
        rec["bytes"], rec["lines"] = len(raw), 1
        self.manifest["services"][0]["baseline_rules"] = 1
        self.save()
        with self.assertRaisesRegex(ValueError, "Unreviewed rule type"):
            mod.build_outputs(self.root)

    def test_rejects_renamed_output_path(self):
        self.manifest["services"][0]["published_path"] = "rules/SomeoneElse.list"
        self.save()
        with self.assertRaisesRegex(ValueError, "published path"):
            mod.build_outputs(self.root)

    def test_rejects_missing_attribution_license(self):
        (self.root / mod.LICENSE).unlink()
        with self.assertRaisesRegex(ValueError, "Missing redistributed"):
            mod.build_outputs(self.root)

    def test_rejects_large_rule_count_drop(self):
        self.manifest["services"][0]["baseline_rules"] = 10
        self.save()
        with self.assertRaisesRegex(ValueError, "decrease"):
            mod.build_outputs(self.root)


if __name__ == "__main__":
    unittest.main()
