"""Offline tests: test-only RULE-SET compiler, attribution and fail-closed lint."""
import hashlib
import sys
from pathlib import Path
from unittest import mock
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import export_advertising_lite_test_artifact as exporter

FAKE_LICENSE = (
    "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"
    + "license body placeholder\n" * 700
    + "END OF TERMS AND CONDITIONS\n"
)


class ExporterTests(unittest.TestCase):
    def test_license_requires_complete_upstream_gpl3(self):
        with self.assertRaisesRegex(ValueError, "license"):
            exporter.verify_license("GPL 3")
        exporter.verify_license(FAKE_LICENSE)

    def test_rule_lint_rejects_surge_invalid_line_and_unreviewed_hash(self):
        lines = ["DOMAIN,ads.example.com"]
        data = "\n".join(lines) + "\n"
        digest = hashlib.sha256(data.encode()).hexdigest()
        metadata = {"candidate_sha256": digest, "candidate_rules": 1,
                    "native_ip_rules_omitted": 13,
                    "native_functionality_rules_omitted": 8}
        with (mock.patch.object(exporter, "EXPECTED_RULE_COUNT", 1),
              mock.patch.object(exporter, "EXPECTED_CANONICAL_SHA256", digest)):
            self.assertEqual(exporter.verify_rules(lines, metadata), data)
            with self.assertRaisesRegex(ValueError, "rule"):
                exporter.verify_rules(["RULE-SET,https://example.com/a.list"], metadata)
            with self.assertRaisesRegex(ValueError, "rule"):
                exporter.verify_rules(["DOMAIN,ads.example.com,REJECT"], metadata)
            with self.assertRaisesRegex(ValueError, "rule"):
                exporter.verify_rules(["DOMAIN,ads.example.com,no-resolve"], metadata)
            with self.assertRaisesRegex(ValueError, "IP"):
                exporter.verify_rules(
                    ["DOMAIN,ads.example.com"],
                    {**metadata, "native_ip_rules_omitted": 10})
        with mock.patch.object(exporter, "EXPECTED_RULE_COUNT", 1):
            with self.assertRaisesRegex(ValueError, "hash"):
                exporter.verify_rules(lines, metadata)

    def test_artifact_contains_license_notice_and_only_valid_rules(self):
        lines = ["DOMAIN,ads.example.com", "DOMAIN-KEYWORD,-ad.video.example.net"]
        canonical = "\n".join(sorted(lines)) + "\n"
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        metadata = {"candidate_sha256": digest, "candidate_rules": 2,
                    "native_ip_rules_omitted": 13,
                    "native_functionality_rules_omitted": 8}
        with (mock.patch.object(exporter, "EXPECTED_RULE_COUNT", 2),
              mock.patch.object(exporter, "EXPECTED_CANONICAL_SHA256", digest),
              mock.patch.object(exporter, "_assemble_candidate",
                                return_value=(sorted(lines), metadata))):
            files = exporter.build_files(b"unused", b"unused", FAKE_LICENSE)
        self.assertEqual(
            set(files),
            {"Advertising-Lite-TEST.list", "LICENSE.GPL-3.0.txt",
             "THIRD_PARTY_NOTICES.md", "manifest.json"}
        )
        rule_lines = [line for line in files["Advertising-Lite-TEST.list"].splitlines()
                      if not line.startswith("#")]
        self.assertEqual(rule_lines, sorted(lines))
        self.assertIn("GNU GENERAL PUBLIC LICENSE", files["LICENSE.GPL-3.0.txt"])
        self.assertIn("Peter Lowe", files["THIRD_PARTY_NOTICES.md"])
        self.assertIn("AWAvenue", files["THIRD_PARTY_NOTICES.md"])
        self.assertNotIn("RULE-SET,https:", files["Advertising-Lite-TEST.list"])

    def test_hash_is_of_canonical_lines_not_header(self):
        lines = ["DOMAIN,ads.example.com"]
        sha = hashlib.sha256((lines[0] + "\n").encode()).hexdigest()
        m = {"candidate_sha256": sha, "candidate_rules": 1,
             "native_ip_rules_omitted": 13, "native_functionality_rules_omitted": 8}
        with (mock.patch.object(exporter, "EXPECTED_RULE_COUNT", 1),
              mock.patch.object(exporter, "EXPECTED_CANONICAL_SHA256", sha),
              mock.patch.object(exporter, "_assemble_candidate", return_value=(lines, m))):
            out = exporter.build_files(b"", b"", FAKE_LICENSE)
        import json
        report = json.loads(out["manifest.json"])
        self.assertEqual(report["candidate_sha256"], sha)
        self.assertNotEqual(report["list_sha256"], sha)
        self.assertEqual(report["candidate_rules"], 1)


if __name__ == "__main__":
    unittest.main()
