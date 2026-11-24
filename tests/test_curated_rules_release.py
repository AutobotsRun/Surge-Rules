"""Offline integrity gate for the curated release candidate.

New releases require an explicit manifest review. This test never downloads
upstreams or changes a profile, AdGuard Home, or a branch.
"""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config/curated-rules-release.json"

def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def rules(raw):
    return [line.strip() for line in raw.decode("utf-8").splitlines()
            if line.strip() and not line.strip().startswith(("#", "!", ";", "//"))]

class CuratedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.sets = {}
        for entry in self.manifest["sets"]:
            raw = (ROOT / entry["file"]).read_bytes()
            self.assertEqual(git_blob(raw), entry["git_blob"], entry["file"])
            active = rules(raw)
            self.assertEqual(len(active), entry["count"])
            self.assertEqual(len(active), len(set(active)))
            self.sets[entry["file"]] = active

    def test_reviewed_counts_and_syntax(self):
        self.assertEqual({k:len(v) for k,v in self.sets.items()}, {
            "rules/Advertising-Lite.list":2890,
            "rules/Privacy-Curated.list":39935,
            "rules/Hijacking-Curated.list":227,
        })
        for name, active in self.sets.items():
            for line in active:
                self.assertIn(line.split(",", 1)[0], {
                    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR"
                }, name)
                self.assertGreater(len(line.split(",", 1)), 1)
        self.assertTrue(all(not r.startswith("IP-CIDR,")
                            for r in self.sets["rules/Advertising-Lite.list"]))

    def test_safe_browsing_decisions(self):
        privacy = self.sets["rules/Privacy-Curated.list"]
        self.assertNotIn("DOMAIN,safebrowsing.googleapis.com", privacy)
        self.assertIn("DOMAIN,safebrowsing.urlsec.qq.com", privacy)
        self.assertIn("DOMAIN-SUFFIX,googleapis.com",
                      rules((ROOT/"rules/Google.list").read_bytes()))

    def test_hijacking_retained(self):
        hijacking = self.sets["rules/Hijacking-Curated.list"]
        self.assertNotIn("DOMAIN,geo2.adobe.com", hijacking)
        self.assertEqual(sum(r.startswith("IP-CIDR,") for r in hijacking), 42)
        self.assertIn("IP-CIDR,114.119.160.0/21,no-resolve", hijacking)
        self.assertTrue(any(r.startswith("IP-CIDR,222.186.61.96/31") for r in hijacking))

    def test_no_dns_policy_change(self):
        raw = (ROOT/"adguard/allowlist.txt").read_bytes()
        self.assertEqual(git_blob(raw),
                         self.manifest["unchanged"]["adguard_allowlist_git_blob"])
        self.assertEqual(sorted(rules(raw)), sorted([
            "@@||apd-pcdnwxlogin.teg.tencent-cloud.net^",
            "@@||apd-pcdnwxstat.teg.tencent-cloud.net^",
            "@@||dns.weixin.qq.com.cn^",
            "@@||smartpay-admin.fugetech.com^",
        ]))

    def test_licenses_and_rollback_available(self):
        self.assertTrue((ROOT/"sources/awavenue/LICENSE").is_file())
        self.assertTrue((ROOT/"sources/blackmatrix7/LICENSE").is_file())
        self.assertTrue((ROOT/"rules/Advertising.list").is_file())
        self.assertTrue((ROOT/"docs/CURATED-RULES-NOTICES.md").is_file())

if __name__ == "__main__":
    unittest.main()
