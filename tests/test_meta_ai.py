import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class MetaAIRulesTests(unittest.TestCase):
    def test_focused_scope_and_license(self):
        source = (ROOT / "sources/v2fly/meta.txt").read_text().splitlines()
        license_text = (ROOT / "sources/v2fly/LICENSE").read_text()
        self.assertIn("MIT License", license_text)
        self.assertIn("Copyright (c) 2018-2019 V2Ray", license_text)
        selected = ["meta.ai", "metaaiusercontent.com", "metaaivm.com"]
        for domain in selected:
            self.assertIn(domain, source)
        rows = [x.strip() for x in (ROOT / "rules/MetaAI.list").read_text().splitlines() if x.strip() and not x.lstrip().startswith("#")]
        expected = ["DOMAIN-SUFFIX," + d for d in selected] + ["DOMAIN,ai.meta.com", "DOMAIN,auth.meta.com"]
        self.assertEqual(rows, expected)

if __name__ == "__main__":
    unittest.main()
