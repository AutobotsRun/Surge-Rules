"""Offline regression tests: universal coverage, ordered routing caveats and pins."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_privacy_hijacking as audit


class RuleOverlapTests(unittest.TestCase):
    def test_parse_and_fail_closed(self):
        source = (b"# comment\nDOMAIN,exact.example.com\n"
                  b"DOMAIN-SUFFIX,example.net\n"
                  b"DOMAIN-KEYWORD,analytics.\n"
                  b"IP-CIDR,1.1.1.1/32,no-resolve\n")
        book = audit.parse_rules(source)
        self.assertEqual(len(book["DOMAIN"]), 1)
        self.assertEqual(len(book["DOMAIN-SUFFIX"]), 1)
        self.assertEqual(len(book["IP-CIDR"]), 1)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit.parse_rules(b"DOMAIN,a.example\nDOMAIN,a.example\n")
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            audit.parse_rules(b"RULE-SET,https://example.com/x.list\n")
        with self.assertRaisesRegex(ValueError, "IP rule flags"):
            audit.parse_rules(b"IP-CIDR,1.1.1.1/32,unsupported\n")

    def test_suffix_boundaries_and_keyword(self):
        p = audit.parse_rules(
            b"DOMAIN-SUFFIX,example.com\nDOMAIN-KEYWORD,analytics.\n")
        self.assertEqual(audit.host_match("foo.example.com", p), "DOMAIN-SUFFIX")
        self.assertIsNone(audit.host_match("notexample.com", p))
        self.assertEqual(audit.host_match("analytics.other.org", p), "DOMAIN-KEYWORD")
        self.assertEqual(audit.covered("DOMAIN-SUFFIX", "foo.example.com", p),
                         "DOMAIN-SUFFIX")
        self.assertIsNone(audit.covered("DOMAIN-SUFFIX", "other.org", p))
        self.assertIsNone(audit.covered("DOMAIN-KEYWORD", "adserver", p))

    def test_exact_lite_host_covered_by_privacy_suffix(self):
        lite = audit.parse_rules(b"DOMAIN,pixel.example.com\n")
        p = audit.parse_rules(b"DOMAIN-SUFFIX,example.com\n")
        self.assertEqual(
            audit.compare(lite, p)["total_rules_fully_covered"], 1)
        # The inverse is false: one exact name cannot cover the entire suffix.
        self.assertEqual(
            audit.compare(p, lite)["total_rules_fully_covered"], 0)

    def test_keyword_coverage_requires_implication_not_intersection(self):
        p = audit.parse_rules(b"DOMAIN-KEYWORD,analytics.\n")
        lite = audit.parse_rules(
            b"DOMAIN-SUFFIX,analytics.example.com\n"
            b"DOMAIN-KEYWORD,analytics.example\n")
        self.assertEqual(
            audit.compare(lite, p)["total_rules_fully_covered"], 2)
        self.assertEqual(
            audit.compare(p, lite)["total_rules_fully_covered"], 0)

    def test_cidr_subnet_containment_and_overlap(self):
        p = audit.parse_rules(b"IP-CIDR,10.0.0.0/24\n")
        l = audit.parse_rules(b"IP-CIDR,10.0.0.1/32,no-resolve\n")
        self.assertEqual(audit.compare(l, p)["total_rules_fully_covered"], 1)
        self.assertEqual(audit.compare(p, l)["total_rules_fully_covered"], 0)
        self.assertIsNone(audit.covered("DOMAIN", "abc.example", p))

    def test_security_endpoint_review_is_only_static_classification(self):
        books = {name: audit.parse_rules(b"") for name in
                 ("privacy", "lite", "hijacking", "china")}
        books["privacy"] = audit.parse_rules(
            b"DOMAIN,safebrowsing.googleapis.com\n"
            b"DOMAIN,safebrowsing.urlsec.qq.com\n"
        )
        result = audit.audit(books)["security_endpoint_review"]
        self.assertTrue(result["safebrowsing.googleapis.com"]["privacy"])
        self.assertTrue(result["safebrowsing.urlsec.qq.com"]["privacy"])
        self.assertFalse(result["safebrowsingohttpgateway.googleapis.com"]["privacy"])
        self.assertFalse(result["safebrowsingohttpgateway.googleapis.com"]["lite"])
        self.assertFalse(result["safebrowsingohttpgateway.googleapis.com"]["hijacking"])

    def test_china_suffix_cover_is_not_reject_equivalence(self):
        china = audit.parse_rules(b"DOMAIN-SUFFIX,cn\n")
        hijack = audit.parse_rules(b"DOMAIN-SUFFIX,flash.cn\n")
        self.assertEqual(
            audit.compare(hijack, china)["total_rules_fully_covered"], 1)
        # Rules with identical predicates but opposite policy outcomes are not
        # interchangeable (Hijacking = REJECT; China = Direct).
        self.assertEqual(
            audit.compare(china, hijack)["total_rules_fully_covered"], 0)


if __name__ == "__main__":
    unittest.main()
