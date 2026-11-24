import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class ApplePushTests(unittest.TestCase):
    def test_existing_suffixes_exactly(self):
        rows = [x.strip() for x in (ROOT / 'rules/Apple-Push.list').read_text().splitlines()
                if x.strip() and not x.lstrip().startswith('#')]
        self.assertEqual(rows, ['DOMAIN-SUFFIX,push.apple.com',
                                'DOMAIN-SUFFIX,push-apple.com.akadns.net'])

if __name__ == '__main__':
    unittest.main()
