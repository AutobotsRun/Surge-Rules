import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class GarminRulesTests(unittest.TestCase):
    def test_focused_scope(self):
        rows = [x.strip() for x in (ROOT / "rules/Garmin.list").read_text().splitlines() if x.strip() and not x.lstrip().startswith("#")]
        expected = ["DOMAIN-SUFFIX,connect.garmin.com","DOMAIN,connectapi.garmin.com","DOMAIN,diauth.garmin.com","DOMAIN,account.customer.services.garmin.com","DOMAIN,mobile-auth.security.services.garmin.com","DOMAIN,apps.garmin.com"]
        self.assertEqual(rows, expected)
        self.assertEqual(len(rows), len(set(rows)))
        def matches(host):
            for row in rows:
                kind, value = row.split(",", 1)
                if host == value or (kind == "DOMAIN-SUFFIX" and host.endswith("." + value)):
                    return True
            return False
        for host in ("sports.garmin.com", "services.garmin.com", "api.gcs.garmin.com", "static.garmin.com", "download.garmin.com", "garmin.com", "sso.garmin.com"):
            self.assertFalse(matches(host), host)
        self.assertTrue(matches("connect.garmin.com"))
        self.assertTrue(matches("test.connect.garmin.com"))
        self.assertTrue(matches("connectapi.garmin.com"))

if __name__ == "__main__":
    unittest.main()
