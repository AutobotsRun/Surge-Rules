"""Offline safety tests for memory-only Lite preview. No public source downloads."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import preview_advertising_lite as preview


class PreviewTests(unittest.TestCase):
    def test_quarantine_native_ip_and_sensitive_exact_hosts(self):
        src = (b"DOMAIN,ads.example.net\n"
               b"DOMAIN,wxa.wxs.qq.com\n"
               b"DOMAIN-KEYWORD,-ad.example.net\n"
               b"IP-CIDR,8.8.8.8/32,no-resolve\n")
        native, skipped_ip, skipped_sensitive = preview.parse_native(src)
        self.assertEqual(skipped_ip, 1)
        self.assertEqual(skipped_sensitive, {"wxa.wxs.qq.com"})
        self.assertEqual(native, {("DOMAIN", "ads.example.net"),
                                  ("DOMAIN-KEYWORD", "-ad.example.net")})

    def test_strict_hosts_parser_rejects_unknown_records(self):
        self.assertEqual(preview.parse_peter_hosts(b"0.0.0.0 ads.example.com\n"),
                         {"ads.example.com"})
        with self.assertRaisesRegex(ValueError, "unsupported"):
            preview.parse_peter_hosts(b"||ads.example.com^\n")
        with self.assertRaisesRegex(ValueError, "invalid"):
            preview.parse_peter_hosts(b"0.0.0.0 not_a_domain\n")

    def test_preview_is_deterministic_and_never_reintroduces_watchlist(self):
        native = (b"DOMAIN,ads.example.net\n"
                  b"DOMAIN-SUFFIX,track.example.net\n"
                  b"DOMAIN,wxa.wxs.qq.com\n"
                  b"DOMAIN-KEYWORD,-ad.example.net\n"
                  b"IP-CIDR,8.8.8.8/32,no-resolve\n")
        hosts = (b"0.0.0.0 pixel.track.example.net\n"
                 b"0.0.0.0 wxa.wxs.qq.com\n"
                 b"0.0.0.0 pixel.example.net\n")
        one = preview.build_preview(native, hosts)
        self.assertEqual(one["native_rules_included"], 3)
        self.assertEqual(one["native_ip_rules_omitted"], 1)
        self.assertEqual(one["native_functionality_rules_omitted"], 1)
        self.assertEqual(one["peter_exact_domains_added"], 1)
        self.assertEqual(one["candidate_rules"], 4)
        other = preview.build_preview(
            b"\n".join(reversed(native.strip().splitlines())) + b"\n",
            b"\n".join(reversed(hosts.strip().splitlines())) + b"\n"
        )
        self.assertEqual(one["candidate_sha256"], other["candidate_sha256"])

    def test_fail_closed_if_protected_host_matches_suffix(self):
        native = b"DOMAIN-SUFFIX,tencent-cloud.net\n"
        hosts = b"0.0.0.0 ads.example.net\n"
        with self.assertRaisesRegex(ValueError, "known-good"):
            preview.build_preview(native, hosts)

    def test_fail_closed_if_protected_host_in_peter_source(self):
        native = b"DOMAIN,ads.example.net\n"
        hosts = b"0.0.0.0 smartpay-admin.fugetech.com\n"
        with self.assertRaisesRegex(ValueError, "known-good"):
            preview.build_preview(native, hosts)

    def test_fail_closed_if_keyword_catches_functional_host(self):
        native = (b"DOMAIN,ads.example.net\n"
                  b"DOMAIN-KEYWORD,-drm.vodplayvideo.net\n")
        hosts = b"0.0.0.0 some.advertising-domain.net\n"
        with self.assertRaisesRegex(ValueError, "functional"):
            preview.build_preview(native, hosts)

    def test_fail_closed_for_broad_keywords_and_ip_flags(self):
        with self.assertRaisesRegex(ValueError, "too broad"):
            preview.parse_native(b"DOMAIN-KEYWORD,ad\n")
        with self.assertRaisesRegex(ValueError, "IP syntax"):
            preview.parse_native(b"IP-CIDR,8.8.8.8/32\n")


if __name__ == "__main__":
    unittest.main()
