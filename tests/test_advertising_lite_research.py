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


if __name__ == "__main__":
    unittest.main()
