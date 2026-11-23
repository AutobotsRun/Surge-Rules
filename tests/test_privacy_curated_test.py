"""Offline regression tests for single-deletion, fail-closed Privacy candidate."""
import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_privacy_curated_test as m

RAW = (
    b"# NAME: Privacy\n"
    b"# AUTHOR: blackmatrix7\n"
    b"DOMAIN,a.example.org\n"
    b"DOMAIN,safebrowsing.googleapis.com\n"
    b"DOMAIN,safebrowsing.urlsec.qq.com\n"
    b"DOMAIN-SUFFIX,tracker.example.com\n"
)


def prepared(raw=RAW):
    return (
        patch.object(m, "SOURCE_SHA", m.git_blob_hash(raw)),
        patch.object(m, "BASELINE_COUNT", 4),
        patch.object(m, "EXPECTED_COUNT", 3),
    )


class TestPrivacyCurated(unittest.TestCase):
    def test_only_one_explicit_domain_removed(self):
        first, second, third = prepared()
        with first, second, third:
            payload, manifest = m.curate(RAW)
        self.assertEqual(manifest["curated_rule_count"], 3)
        self.assertEqual(manifest["deleted_rule"], "DOMAIN,safebrowsing.googleapis.com")
        self.assertNotIn(b"DOMAIN,safebrowsing.googleapis.com\n", payload)
        self.assertIn(b"DOMAIN,safebrowsing.urlsec.qq.com\n", payload)
        self.assertTrue(payload.endswith(
            RAW.replace(b"DOMAIN,safebrowsing.googleapis.com\n", b"")
        ))
        self.assertEqual(
            manifest["candidate_sha256"], hashlib.sha256(payload).hexdigest()
        )

    def test_missing_rule_rejected(self):
        altered = RAW.replace(b"DOMAIN,safebrowsing.googleapis.com\n", b"")
        with patch.object(m, "SOURCE_SHA", m.git_blob_hash(altered)), \
                patch.object(m, "BASELINE_COUNT", 3), \
                patch.object(m, "EXPECTED_COUNT", 2):
            with self.assertRaisesRegex(ValueError, "missing exact"):
                m.curate(altered)

    def test_unexpected_new_upstream_blob_rejected(self):
        with self.assertRaisesRegex(ValueError, "Git blob changed"):
            m.curate(RAW)

    def test_duplicate_rule_rejected(self):
        altered = RAW + b"DOMAIN,safebrowsing.googleapis.com\n"
        with patch.object(m, "SOURCE_SHA", m.git_blob_hash(altered)), \
                patch.object(m, "BASELINE_COUNT", 5), \
                patch.object(m, "EXPECTED_COUNT", 4):
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                m.curate(altered)

    def test_modified_other_rule_rejected_by_sha(self):
        altered = RAW.replace(b"DOMAIN,a.example.org", b"DOMAIN,other.example.org")
        first, second, third = prepared()
        with first, second, third:
            with self.assertRaisesRegex(ValueError, "Git blob changed"):
                m.curate(altered)

    def test_bad_syntax_fail_closed(self):
        raw = RAW + b"RULE-SET,https://example.com/list\n"
        with patch.object(m, "SOURCE_SHA", m.git_blob_hash(raw)), \
                patch.object(m, "BASELINE_COUNT", 5), \
                patch.object(m, "EXPECTED_COUNT", 4):
            with self.assertRaisesRegex(ValueError, "Unexpected rule"):
                m.curate(raw)

    def test_non_lf_input_rejected(self):
        raw = RAW.replace(b"\n", b"\r\n")
        first, second, third = prepared(raw)
        with first, second, third:
            with self.assertRaisesRegex(ValueError, "LF-terminated"):
                m.curate(raw)

    def test_not_duplicate_or_broad_google_bypass(self):
        # The candidate fixes only Privacy; it does not modify Google list
        # or move its hundreds of service rules above Privacy.
        self.assertEqual(m.TARGET, b"DOMAIN,safebrowsing.googleapis.com")
        self.assertEqual(m.EXPECTED_COUNT, 39935)


if __name__ == "__main__":
    unittest.main()
