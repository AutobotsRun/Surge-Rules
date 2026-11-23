# THIRD-PARTY NOTICES — Advertising Lite TEST ONLY

This experimental bundle combines third-party entries, including derived AWAvenue rules. It is not original-only content and is not an upstream-endorsed release.

## AWAvenue — TG-Twilight and contributors

- Project: https://github.com/TG-Twilight/AWAvenue-Ads-Rule
- Audited source: https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Surge-RULE-SET-Only.Ads.list
- Original license: GNU General Public License version 3. The accompanying LICENSE.GPL-3.0.txt reproduces the upstream full license.
- Modifications: omit 13 IP-CIDR rules while awaiting IP ownership review; quarantine 8 exact potential functionality endpoints; sort, deduplicate and combine only supported domain/keyword entries. These exclusions are precautionary, not proven upstream bugs.

## Peter Lowe

- Project and reuse permission: https://pgl.yoyo.org/as/
- List selection: https://pgl.yoyo.org/as/serverlist.php?hostformat=hosts&notrackers=1&showintro=0&mimetype=plaintext
- Original author explicitly permits merging the list with other sources and publishing the combination.
- Modifications: convert HOSTS names to exact Surge DOMAIN rules, deduplicate against retained native domain/suffix predicates, and avoid introducing the eight quarantined hosts.

## Integrity, safety and reproducibility

- Upstream input SHA256 pinned in scripts/preview_advertising_lite.py.
- Deterministic rules SHA256 (without comment header): 92cdd3dd0eed603d9eb153fed92b06ef8dd9d21ef949df883ac29c098ffdf632
- Output list SHA256 (with comment header): 240347ee54b5baee112535ea647a8cce4878bba5b971924072066bdedf8ed0a7
- This is a static, non-auto-updating snapshot.
- Public research, tests and source code: https://github.com/AutobotsRun/Surge-Rules/pull/12
- This artifact is a prototype for a spare-device A/B test, not a recommendation for production use; existing Surge and AdGuard Home configurations are not changed by this build.
