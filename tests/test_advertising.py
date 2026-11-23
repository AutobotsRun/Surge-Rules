"""Unit tests for fail-closed exclusion processing (no network or Surge changes)."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/build_advertising.py"
spec = importlib.util.spec_from_file_location("build_advertising", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

TARGET = "DOMAIN,apd-pcdnwxlogin.teg.tencent-cloud.net"
EXCLUSIONS = {TARGET}


class AdvertisingExclusionTests(unittest.TestCase):
    def test_exact_rule_is_removed_without_affecting_others(self):
        data = ("# HEAD\nDOMAIN,ads.example.com\n" + TARGET + "\nDOMAIN,tracker.example.org\n").encode()
        result, removed, original_count = mod.transform(data, EXCLUSIONS, strict=False)
        self.assertEqual(removed, [TARGET])
        self.assertEqual(original_count, 3)
        self.assertNotIn(TARGET, result)
        self.assertIn("DOMAIN,ads.example.com", result)
        self.assertIn("DOMAIN,tracker.example.org", result)

    def test_missing_expected_rule_blocks_release(self):
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            mod.transform(b"DOMAIN,ads.example.com\n", EXCLUSIONS, strict=False)

    def test_duplicate_expected_rule_blocks_release(self):
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            mod.transform((TARGET + "\n" + TARGET + "\n").encode(), EXCLUSIONS, strict=False)

    def test_broad_domain_suffix_blocks_release(self):
        data = (TARGET + "\nDOMAIN-SUFFIX,teg.tencent-cloud.net\n").encode()
        with self.assertRaisesRegex(ValueError, "Potential remaining"):
            mod.transform(data, EXCLUSIONS, strict=False)

    def test_domain_keyword_blocks_release(self):
        data = (TARGET + "\nDOMAIN-KEYWORD,pcdnwx\n").encode()
        with self.assertRaisesRegex(ValueError, "Potential remaining"):
            mod.transform(data, EXCLUSIONS, strict=False)

    def test_regex_requires_review(self):
        data = (TARGET + "\nURL-REGEX,https://example.com/ads\n").encode()
        with self.assertRaisesRegex(ValueError, "Potential remaining"):
            mod.transform(data, EXCLUSIONS, strict=False)

    def test_html_blocks_release(self):
        with self.assertRaisesRegex(ValueError, "HTML"):
            mod.transform(b"<html>failure</html>", EXCLUSIONS, strict=False)


if __name__ == "__main__":
    unittest.main()
