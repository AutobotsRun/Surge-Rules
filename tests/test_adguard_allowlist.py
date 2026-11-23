"""Validate published AdGuard Home DNS exceptions without network access."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "adguard/allowlist.txt"
REQUIRED = {
    "apd-pcdnwxlogin.teg.tencent-cloud.net",
    "apd-pcdnwxstat.teg.tencent-cloud.net",
    "dns.weixin.qq.com.cn",
    "smartpay-admin.fugetech.com",
}
PATTERN = re.compile(r"@@\\|\\|([a-z0-9-]+(?:\\.[a-z0-9-]+)+)\\^")


class AdGuardAllowlistTests(unittest.TestCase):
    def test_only_narrow_exception_rules_and_no_duplicates(self):
        entries = [line.strip() for line in ALLOWLIST.read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
        self.assertTrue(entries)
        domains = []
        for entry in entries:
            match = PATTERN.fullmatch(entry)
            self.assertIsNotNone(match, f"Invalid or broad exception: {entry}")
            domain = match.group(1)
            self.assertTrue(all(not label.startswith("-") and not label.endswith("-")
                                and len(label) <= 63 for label in domain.split(".")))
            domains.append(domain)
        self.assertEqual(len(domains), len(set(domains)), "Duplicate DNS exception")
        self.assertTrue(REQUIRED.issubset(domains), "A verified exception was removed")


if __name__ == "__main__":
    unittest.main()
