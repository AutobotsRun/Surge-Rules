import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class DirectExceptionsTests(unittest.TestCase):
    def test_exact_reviewed_hosts(self):
        rows = [x.strip() for x in (ROOT / "rules/Direct-Exceptions.list").read_text().splitlines() if x.strip() and not x.lstrip().startswith("#")]
        expected = ["DOMAIN,apd-pcdnwxlogin.teg.tencent-cloud.net","DOMAIN,apd-pcdnwxstat.teg.tencent-cloud.net","DOMAIN,dns.weixin.qq.com.cn","DOMAIN,smartpay-admin.fugetech.com"]
        self.assertEqual(rows, expected)
        self.assertEqual(len(rows), len(set(rows)))
        for row in rows:
            self.assertRegex(row, r"^DOMAIN,[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
            host = row.split(",", 1)[1]
            self.assertNotIn("DOMAIN,test." + host, rows)
            self.assertIn(host, (ROOT / "docs/DIRECT-EXCEPTIONS.md").read_text())

if __name__ == "__main__":
    unittest.main()
