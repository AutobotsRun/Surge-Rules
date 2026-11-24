# Curated rule sets — third-party notices

Release candidate: 2026.11.24-rc1. These are independently maintained rule snapshots, not upstream-endorsed releases. No automatic device deployment.

## Advertising Lite

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



The complete GNU GPL v3 license is at [sources/awavenue/LICENSE](../sources/awavenue/LICENSE).
The original artifact and source fingerprint manifest are preserved at the [immutable tested commit](https://github.com/AutobotsRun/Surge-Rules/tree/41cc017763ae9ef2127eac28be1effd11ef1080e/experiments/advertising-lite). Build/research scripts, tests and original notices are available in [PR #12](https://github.com/AutobotsRun/Surge-Rules/pull/12). The released candidate has exactly the same 2,890 matching lines in the same order as that artifact; only release comments changed. The 13 IP entries and eight precautionary host exclusions remain omitted.

## Privacy Curated and Hijacking Curated

Original author: blackmatrix7, [ios_rule_script](https://github.com/blackmatrix7/ios_rule_script), GPL-2.0. Full license: [sources/blackmatrix7/LICENSE](../sources/blackmatrix7/LICENSE).

- Privacy: original Git blob a75df944a7a0fcae26f762059c0f7fd72f42c420; removed only DOMAIN,safebrowsing.googleapis.com. Retained 39,935 predicates including DOMAIN,safebrowsing.urlsec.qq.com. Original source comment totals refer to the upstream snapshot, not the curated count. Build source and tests: [PR #14](https://github.com/AutobotsRun/Surge-Rules/pull/14).
- Hijacking: original Git blob 0ffb798f0ce5f098fd3e7dc889fbbca94b9bdd5d; removed only DOMAIN,geo2.adobe.com. Retained all other 227 predicates, including every original IPv4 network block. Source and build tests: [PR #13](https://github.com/AutobotsRun/Surge-Rules/pull/13).

Independent release files retain the original upstream notices and the exact reviewed predicate sequences. The respective third-party licenses govern their files; the sets are distributed as separate files, not merged into one differently licensed rule corpus.
