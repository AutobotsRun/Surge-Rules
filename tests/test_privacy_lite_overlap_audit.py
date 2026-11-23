"""Offline coverage tests; no network access or user data."""
import hashlib
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_privacy_lite_overlap as audit


class RuleAuditTests(unittest.TestCase):
    def test_git_blob_sha_uses_bytes_not_raw_sha(self):
        self.assertEqual(audit.git_blob_sha(b"hello\n"),
                         hashlib.sha1(b"blob 6\0hello\n").hexdigest())

    def test_pinned_source_fetch_fails_closed(self):
        class FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def read(self):
                return b"changed"
        with patch.object(audit, "urlopen", return_value=FakeResponse()):
            with self.assertRaisesRegex(ValueError, "changed"):
                audit.fetch_checked("https://example.com/feed", "bad-sha")

    def test_native_types_and_counts(self):
        data = (b"# source header\n"
                b"DOMAIN,a.example\n"
                b"DOMAIN-SUFFIX,example.com\n"
                b"DOMAIN-KEYWORD,analytics.\n"
                b"IP-CIDR,1.2.3.4/32,no-resolve\n"
                b"USER-AGENT,App*\n")
        self.assertEqual(
            audit.parse(data),
            [("DOMAIN", "a.example"), ("DOMAIN-SUFFIX", "example.com"),
             ("DOMAIN-KEYWORD", "analytics."),
             ("IP-CIDR", "1.2.3.4/32"), ("USER-AGENT", "app*")])
        with self.assertRaisesRegex(ValueError, "unexpected rule"):
            audit.parse(b"UNKNOWN,example.org\n")
        with self.assertRaisesRegex(ValueError, "unexpected rule flag"):
            audit.parse(b"IP-CIDR,8.8.8.8/32,resolve\n")
        with self.assertRaisesRegex(ValueError, "domain flag"):
            audit.parse(b"DOMAIN,example.org,no-resolve\n")

    def test_exact_suffix_and_keyword_entailment(self):
        index = audit.DomainIndex([
            ("DOMAIN", "exact.example.com"),
            ("DOMAIN-SUFFIX", "private.example.com"),
            ("DOMAIN-KEYWORD", "analytics."),
        ])
        self.assertEqual(index.covers(("DOMAIN", "exact.example.com")), "exact")
        self.assertEqual(index.covers(("DOMAIN", "api.private.example.com")),
                         "suffix")
        self.assertEqual(index.covers(("DOMAIN-SUFFIX", "a.private.example.com")),
                         "suffix")
        self.assertEqual(index.covers(("DOMAIN", "analytics.foo.com")),
                         "keyword")
        self.assertEqual(index.covers(("DOMAIN-KEYWORD", "app-analytics.")),
                         "keyword")
        self.assertEqual(index.covers(("DOMAIN-SUFFIX", "analytics.foo.com")),
                         "keyword")
        self.assertIsNone(index.covers(("DOMAIN", "private.example.com.evil")))
        self.assertIsNone(index.covers(("DOMAIN-SUFFIX", "example.com")))
        self.assertIsNone(index.covers(("DOMAIN-KEYWORD", "private.example.com")))
        self.assertIsNone(index.covers(("IP-CIDR", "8.8.8.8/32")))
        self.assertTrue(index.host_matches("www.private.example.com"))
        self.assertFalse(index.host_matches("private.example.com.evil"))

    def test_exact_domain_does_not_entail_suffix(self):
        exact_only = audit.DomainIndex([("DOMAIN", "ads.example.net")])
        self.assertIsNone(
            exact_only.covers(("DOMAIN-SUFFIX", "ads.example.net")))
        self.assertEqual(
            exact_only.covers(("DOMAIN", "ads.example.net")), "exact")

    def test_audit_reports_only_complete_predicate_coverage(self):
        sets = {
            "lite": [("DOMAIN", "ads.example.net"), ("DOMAIN", "pixel.example.com")],
            "privacy": [("DOMAIN-SUFFIX", "example.net"),
                        ("DOMAIN", "pixel.example.com")],
            "hijacking": [("IP-CIDR", "1.2.3.4/32")],
            "china": [("DOMAIN", "ads.example.net")],
        }
        with patch.dict(audit.EXPECTED_COUNT,
                        {k: len(v) for k, v in sets.items()}):
            result = audit.audit(sets)
        self.assertEqual(
            result["metrics"]["lite_fully_covered_by_privacy"]["count"], 2)
        self.assertEqual(
            result["metrics"]["privacy_fully_covered_by_lite"]["count"], 1)
        self.assertEqual(
            result["metrics"]["hijacking_fully_covered_by_lite_or_privacy"]["count"], 0)
        self.assertEqual(result["exact_same_type_same_value_lite_privacy"], 1)
        self.assertEqual(result["source_rule_counts"]["lite"], 2)

    def test_count_mismatch_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "unexpected rule count"):
            audit.audit({k: [] for k in audit.EXPECTED_COUNT})


if __name__ == "__main__":
    unittest.main()
