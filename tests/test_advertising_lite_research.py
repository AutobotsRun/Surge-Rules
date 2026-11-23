"""Offline tests for read-only advertising lite comparison."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "scripts/research_advertising_lite.py"
spec = importlib.util.spec_from_file_location("liteaudit", path)
liteaudit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(liteaudit)


class Tests(unittest.TestCase):
    def test_suffix(self):
        self.assertTrue(liteaudit.covered(set(), {"example.com"}, "ads.example.com"))
        self.assertFalse(liteaudit.covered(set(), {"example.com"}, "notexample.com"))
        self.assertFalse(liteaudit.covered({"a.example.com"}, set(), "b.a.example.com"))

    def test_adblock_excludes_unsupported(self):
        d, e = liteaudit.candidate_rules(
            b"||ads.example.com^\n@@||safe.example.com^\n||ads2.example.com^$important\n",
            "adblock")
        self.assertEqual(d, {"ads.example.com"})
        self.assertEqual(e["unsupported_or_exception"], 2)

    def test_hosts(self):
        d, _ = liteaudit.candidate_rules(
            b"0.0.0.0 ad.example.com\n127.0.0.1 tracker.example.net\n"
            b"127.0.0.1 localhost\n", "hosts")
        self.assertEqual(d, {"ad.example.com", "tracker.example.net"})

    def test_surge(self):
        exact, suffix, types = liteaudit.surge_rules(
            b"DOMAIN,a.example.com\nDOMAIN-SUFFIX,b.example.com\n"
            b"DOMAIN-KEYWORD,ads\nIP-CIDR,0.0.0.0/32\n")
        self.assertEqual(exact, {"a.example.com"})
        self.assertEqual(suffix, {"b.example.com"})
        self.assertEqual(sum(types.values()), 4)


    def test_native_surge_uses_exact_suffix_and_keyword_semantics(self):
        native = (
            b"# UPDATED: 2025-12-08 02:03:37\n"
            b"DOMAIN,exact.example.com\n"
            b"DOMAIN-SUFFIX,blocked.example.com\n"
            b"DOMAIN-KEYWORD,adtracking\n"
            b"IP-CIDR,203.0.113.0/24,no-resolve\n"
        )
        exact, suffix, types = liteaudit.surge_rules(native)
        self.assertEqual(exact, {"exact.example.com"})
        self.assertEqual(suffix, {"blocked.example.com"})
        self.assertTrue(liteaudit.covered(exact, suffix, "a.blocked.example.com"))
        self.assertFalse(liteaudit.covered(exact, suffix, "a.exact.example.com"))
        self.assertEqual(sum(types.values()), 4)

    def test_native_ip_audit_counts_risky_scope_without_listing_ips(self):
        native = (
            b"IP-CIDR,203.0.113.0/24,no-resolve\n"
            b"IP-CIDR,8.8.8.8/32,no-resolve\n"
            b"IP-CIDR,1.2.0.0/16\n"
            b"IP-CIDR6,2001:4860:4860::8888/128,no-resolve\n"
            b"IP-CIDR,invalid\n"
            b"IP-CIDR6,8.8.8.8/32\n"
        )
        result = liteaudit.audit_native_ip_rules(native)
        self.assertEqual(result["ipv4"], 3)
        self.assertEqual(result["ipv6"], 1)
        self.assertEqual(result["non_global"], 1)
        self.assertEqual(result["broad_ipv4_under_24"], 1)
        self.assertEqual(result["broad_ipv6_under_64"], 0)
        self.assertEqual(result["invalid"], 2)
        self.assertEqual(result["single_ipv4_32"], 1)
        self.assertEqual(result["single_ipv6_128"], 1)
        self.assertEqual(result["with_no_resolve"], 2)
        self.assertEqual(result["without_no_resolve"], 2)

    def test_hosts_remain_exact_when_compared_to_existing_rules(self):
        exact, unsupported = liteaudit.candidate_rules(
            b"0.0.0.0 ads.example.net\n", "hosts")
        self.assertFalse(unsupported)
        self.assertTrue(liteaudit.covered(exact, set(), "ads.example.net"))
        self.assertFalse(liteaudit.covered(exact, set(), "child.ads.example.net"))


    def test_small_pair_deduplicates_only_semantically_covered_hosts(self):
        native = (
            b"DOMAIN,already.example.com\n"
            b"DOMAIN-SUFFIX,covered.example.com\n"
            b"IP-CIDR,8.8.8.8/32\n"
            b"DOMAIN-KEYWORD,adtracking\n"
        )
        extra = b"".join(
            ("0.0.0.0 example%d.example.net\n" % i).encode()
            for i in range(1200)
        )
        hosts = (
            b"0.0.0.0 already.example.com\n"
            b"0.0.0.0 child.covered.example.com\n" + extra
        )
        result = liteaudit.study_small_pair(native, hosts)
        self.assertEqual(result["native_rules_total"], 4)
        self.assertEqual(result["hosts_ads_only_unique"], 1202)
        self.assertEqual(result["hosts_already_covered_by_native_exact_or_suffix"], 2)
        self.assertEqual(result["estimated_merged_native_rule_count"], 1204)
        self.assertFalse(any(result["known_good_matched_by_domain_or_keyword"].values()))

    def test_suffix_mode_preserves_native_exact_semantics(self):
        native = (
            b"DOMAIN,already.example.com\n"
            b"DOMAIN-SUFFIX,covered.example.com\n"
        )
        extra = b"".join(
            ("0.0.0.0 x%d.adexample.net\n" % i).encode()
            for i in range(1200)
        )
        hosts = (
            b"0.0.0.0 already.example.com\n"
            b"0.0.0.0 child.covered.example.com\n" + extra
        )
        exact = liteaudit.study_small_pair(native, hosts, "exact")
        suffix = liteaudit.study_small_pair(native, hosts, "suffix")
        self.assertEqual(exact["hosts_already_covered_by_native_rules"], 2)
        self.assertEqual(suffix["hosts_already_covered_by_native_rules"], 1)
        self.assertEqual(exact["estimated_merged_native_rule_count"], 1202)
        self.assertEqual(suffix["estimated_merged_native_rule_count"], 1203)

    def test_suffix_expansion_fails_closed_on_verified_good_domain(self):
        native = b"DOMAIN,unrelated.example.com\n"
        hosts = (b"0.0.0.0 tencent-cloud.net\n" +
                 b"".join(("0.0.0.0 x%d.adexample.net\n" % i).encode()
                          for i in range(1200)))
        result = liteaudit.study_small_pair(native, hosts, "exact")
        self.assertFalse(any(result["known_good_matched_by_domain_or_keyword"].values()))
        with self.assertRaisesRegex(ValueError, "known-good"):
            liteaudit.study_small_pair(native, hosts, "suffix")

    def test_unsafe_public_suffix_is_rejected_before_study(self):
        native = b"DOMAIN,unrelated.example.com\n"
        hosts = (b"0.0.0.0 co.uk\n" +
                 b"".join(("0.0.0.0 x%d.adexample.net\n" % i).encode()
                          for i in range(1200)))
        with self.assertRaisesRegex(ValueError, "public suffix"):
            liteaudit.study_small_pair(native, hosts, "suffix")

    def test_sensitive_wechat_hosts_are_review_flags_not_proven_false_positives(self):
        native = b"DOMAIN,wxa.wxs.qq.com\n"
        hosts = b"".join(("0.0.0.0 x%d.adexample.net\n" % i).encode()
                         for i in range(1200))
        pair = liteaudit.study_small_pair(native, hosts, "exact")
        self.assertIn("wxa.wxs.qq.com", pair["native_potential_functional_hosts_for_review"])
        self.assertFalse(any(pair["known_good_matched_by_domain_or_keyword"].values()))


if __name__ == "__main__":
    unittest.main()
