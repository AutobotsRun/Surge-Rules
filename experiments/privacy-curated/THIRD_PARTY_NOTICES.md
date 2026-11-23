# Privacy Curated Test — third-party notices

**This is an experimental, single-rule edited copy, not the default or production Surge subscription.**

Original author and source: **blackmatrix7**, [ios_rule_script](https://github.com/blackmatrix7/ios_rule_script), `rule/Surge/Privacy/Privacy_All.list`.

Source version: Git blob `a75df944a7a0fcae26f762059c0f7fd72f42c420` (39,936 active rules).

**License:** GPL-2.0. The full existing source license is included in this repository at [`sources/blackmatrix7/LICENSE`](../../sources/blackmatrix7/LICENSE).

**Changes made by AutobotsRun:**
- Added comments identifying provenance and test-only status.
- Removed **only** `DOMAIN,safebrowsing.googleapis.com`, an official Google Safe Browsing API host already covered by the pre-existing `Google.list` `DOMAIN-SUFFIX,googleapis.com` route.
- Preserved all other 39,935 active rules and the original source comments/order.

The original `# TOTAL: 39936` and `# DOMAIN: 19` headers reflect the **upstream snapshot**, not the edited test file. This test version's verified effective counts are **39,935 total**, including **18 DOMAIN** and **39,897 DOMAIN-SUFFIX**. Read `manifest.json` for details.

This experimental branch should only be used by a specifically designated test device. Never automatically replace the existing upstream Privacy list on other devices or alter AdGuard Home DNS based on this artifact.
