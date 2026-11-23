"""Offline tests for the one-host Hijacking curation plan."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_hijacking_curated_test as m

RAW = (
    b"# NAME: Hijacking\n"
    b"DOMAIN,geo2.adobe.com\n"
    b"DOMAIN-SUFFIX,bad.example\n"
    b"IP-CIDR,114.119.160.0/21,no-resolve\n"
)


class HijackingCandidateTests(unittest.TestCase):
    def fixture(self, raw=RAW, count=3):
        return (
            patch.object(m, "SOURCE_SHA", m.git_blob_sha(raw)),
            patch.object(m, "ORIGINAL_COUNT", count),
            patch.object(m, "EXPECTED_COUNT", count - 1),
        )

    def test_exactly_one_removed_and_ip_kept(self):
        a, b, c = self.fixture()
        with a, b, c:
            payload, manifest = m.build(RAW)
        self.assertNotIn(b"DOMAIN,geo2.adobe.com\n", payload)
        self.assertIn(b"DOMAIN-SUFFIX,bad.example\n", payload)
        self.assertIn(b"IP-CIDR,114.119.160.0/21,no-resolve\n", payload)
        self.assertTrue(payload.endswith(RAW.replace(m.REMOVED+b"\n", b"")))
        self.assertEqual(manifest["curated_rules"], 2)
        self.assertFalse(manifest["deployed"])

    def test_fails_closed_on_source_change(self):
        with self.assertRaisesRegex(ValueError, "mismatch"):
            m.build(RAW)

    def test_missing_exact_host_is_not_accepted(self):
        altered = RAW.replace(m.REMOVED + b"\n", b"")
        a, b, c = self.fixture(altered, count=2)
        with a, b, c:
            with self.assertRaisesRegex(ValueError, "missing"):
                m.build(altered)

    def test_duplicate_hosts_not_allowed(self):
        altered = RAW + m.REMOVED + b"\n"
        a, b, c = self.fixture(altered, count=4)
        with a, b, c:
            with self.assertRaisesRegex(ValueError, "Duplicated"):
                m.build(altered)

    def test_unknown_rule_type_fails(self):
        altered = RAW + b"RULE-SET,https://example.org/f.list\n"
        a, b, c = self.fixture(altered, count=4)
        with a, b, c:
            with self.assertRaisesRegex(ValueError, "Unexpected"):
                m.build(altered)

    def test_no_extra_domain_flags(self):
        with self.assertRaisesRegex(ValueError, "domain flags"):
            m.parse_rules(b"DOMAIN,example.org,no-resolve\n")

    def test_line_endings_fails(self):
        altered = RAW.replace(b"\n", b"\r\n")
        a, b, c = self.fixture(altered)
        with a, b, c:
            with self.assertRaisesRegex(ValueError, "line endings"):
                m.build(altered)


if __name__ == "__main__":
    unittest.main()
