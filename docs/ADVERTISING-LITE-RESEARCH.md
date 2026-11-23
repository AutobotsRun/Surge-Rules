# Advertising Lite: comparison of three sources

Research stage (November 23, 2026). No new advertising subscription is published or deployed.

Candidates:
- HaGeZi Multi Light: https://github.com/hagezi/dns-blocklists (Adblock format; GPL-3.0).
- AdGuard DNS filter: https://github.com/AdguardTeam/AdGuardSDNSFilter (Adblock/DNS format; GPL-3.0).
- StevenBlack unified base hosts: https://github.com/StevenBlack/hosts (hosts format; attribution and bundled-source licensing need inspection).

The baseline is the actual iPhone 15 Pro pinned Advertising.list at commit 01d9fb3, plus independent Privacy_All.list and Hijacking.list for redundancy analysis.

The read-only workflow retrieves each public source, records sizes and SHA-256, counts simple valid domain predicates, computes approximate overlapping hostnames, and flags the four verified exceptions (WeChat CDN login, WeChat stat, WeChat DNS, SmartPay admin). Results are logged as JSON and archived as a small report. No raw third-party list is redistributed.

Important limits:
- AdGuard rules, hosts entries, and Surge DOMAIN-SUFFIX are not interchangeable. The comparison only normalizes simple domain patterns; exception rules, rule modifiers, IPs, regular expressions, CNAME effects and traffic weights are not represented.
- A source that contains fewer domain strings can still perform worse, or break more sites.
- Do not make a final source selection or publicly mirror third-party entries before license review, conversion tests, and real-device checks.
- Future A/B test must replace rather than stack the advertising subscription, and must be limited to the iPhone 15 Pro. Keep the original full set and its URL intact for immediate rollback.
- This PR does not change the current AdGuard Home or Surge configuration.


## First live-source comparison results (2026-11-23)

CI: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45173796449
Offline validation: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45173796440

| Candidate | Bytes | Simple unique domains | Covered by current Advertising | Not covered by Advertising | Not covered by any of current Advertising / Privacy / Hijacking | Unsupported or exception lines |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HaGeZi Light | 1,933,962 | 76,708 | 24,921 | 51,787 | 50,989 | 0 |
| AdGuard DNS filter | 4,667,343 | 190,058 | 169,659 | 20,399 | 15,933 | 894 |
| StevenBlack base hosts | 2,328,985 | 76,107 | 29,823 | 46,284 | 45,761 | 7 |

Reference from the active pinned Advertising.list: 9,604,834 bytes; 291,173 active rules (16,435 exact DOMAIN, 273,956 DOMAIN-SUFFIX, plus keyword, IP, regex and AND predicates). SHA-256: ed3efe720f6ffa23b44e8923b3fa02091028f00e6cfcb3b40b94ab00e1ab52f7.

Public-source SHA-256 snapshots:
- HaGeZi Light: cdc7388e4b73bbf25fb837806b237efceeeefd6275bbc7e43873721e2f9d8110
- AdGuard DNS filter: 882019ff18fc7ce8e26e11aaea97e8375afe796863190151cf2903c2f09918a1
- StevenBlack hosts: a596c1301ff515f441fb862227ad7eacdb9ded28536905297b03925b45c74f7d

### High-priority false-positive warning

The domain-pattern comparison found:
- HaGeZi Light **would match** apd-pcdnwxlogin.teg.tencent-cloud.net and apd-pcdnwxstat.teg.tencent-cloud.net.
- AdGuard DNS filter **would match** smartpay-admin.fugetech.com.
- StevenBlack base **did not exactly match** any of the four currently approved DNS exceptions in this snapshot.

This is only a *static matcher observation*, not proof that a specific program would fail or which rule has priority in a third-party app. The AdGuard candidate's 894 unparsed lines include non-simple syntax and must not be silently discarded. Hosts domains are treated as exact entries, unlike Adblock suffix syntax.

### Initial decision (not authorization to deploy)

1. Do not copy HaGeZi Light or AdGuard DNS as-is: both still match locally proven false-positive hostnames.
2. StevenBlack is useful as a cleaner initial *reference candidate*, but 76,107 hostnames are not yet a 5k–30k minimal ruleset and over 45k names are not covered by any current simple advertising/privacy/hijacking predicates. This metric alone does not mean more ads would be blocked or safety would improve.
3. Investigate source-subset construction with **strict attribution**, a maintained exact exclusion mechanism, no accidental hosts-to-suffix broadening, and deterministic testing. Explicitly assess the current privacy/hijacking functions before any replacement.
4. Before A/B switching iPhone 15 Pro, complete license review (HaGeZi and AdGuard use GPL-3.0, StevenBlack top-level license is MIT but aggregated inputs require attribution review) and test Surge parsing/indexing. Keep the existing full list unchanged and do not make changes to any other devices.

**Status: research PR remains draft; no Advertising-Lite.list exists yet.**


## Second research round: native Surge Lite and OISD Small (2026-11-23)

Audit (read-only): https://github.com/AutobotsRun/Surge-Rules/actions/runs/45178290951
Offline validation: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45178290956

The comparison now includes five candidates, not three:

| Candidate | Format | Simple predicates | Candidate hostnames covered by current Advertising | Current Advertising exact + suffix predicates conservatively covered by candidate | Known false positives |
| --- | --- | ---: | ---: | ---: | --- |
| Blackmatrix7 AdvertisingLite_All | Native Surge | 37,692 | 37,163 (98.6%) | 26,244 / 290,391 (9.0%) | WeChat PCDN login |
| OISD Small | ABP DNS | 62,315 | 52,027 (83.5%) | 51,739 / 290,391 (17.8%) | Both WeChat PCDN names |
| HaGeZi Light | ABP DNS | 76,708 | 24,921 (32.5%) | 22,714 / 290,391 (7.8%) | Both WeChat PCDN names |
| StevenBlack base | Hosts exact | 76,107 | 29,823 (39.2%) | 1,321 / 290,391 (0.45%) | None of the four |
| AdGuard DNS filter | ABP DNS | 190,058 | 169,659 (89.3%) | 168,587 / 290,391 (58.1%) | SmartPay admin |

IMPORTANT: These are two different directions of comparison. A candidate's hostnames being matched by the old list does NOT mean the candidate retains the same percentage of the original list's blocking. Reverse predicate coverage is also not a real-world blocking-rate estimate. Tests do not account for actual request frequency, complex rules, IP matching, CNAME, exceptions, in-page ads, or region-specific breakage. The reverse test is conservative: a candidate exact-domain rule cannot cover all subdomains of an existing DOMAIN-SUFFIX rule.

### Native Blackmatrix7 AdvertisingLite

- Repository: https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Surge/AdvertisingLite
- Analyzed AdvertisingLite_All.list: 953,816 bytes, SHA-256 0cca6a10810742bcf1e59ff64309801fe89c96fc5000570773c22c8300227974.
- 38,069 valid native rules: DOMAIN 23,753; DOMAIN-SUFFIX 13,939; DOMAIN-KEYWORD 187; IP-CIDR 186; IP-CIDR6 1; URL-REGEX 2; AND 1.
- AdvertisingLite.list alone is only the NON-domain-set portion. Surge 5.21+ should use AdvertisingLite_All.list alone, per its upstream README, not the split file alone.
- Header last updated 2025-12-08 02:03:37, whereas current full Advertising header shows 2026-10-28 05:39:01. Lite is notably stale.
- The upstream README states Lite excludes the Privacy and Hijacking rule categories, though independent overlap still exists.
- Lite still matches the validated WeChat PCDN login hostname. Any derived candidate must use exact, reviewed exclusions.

### OISD Small

- Official list https://small.oisd.nl; official FAQ https://oisd.nl/faq.
- Observed 1,411,894 bytes, 62,315 ABP-style rules, SHA-256 fefc022b58b960ec888a91817a76dd0c908a97972f61bba9cef94054822d5801.
- The maintainer describes it as focused on ads and mobile ads, with typically daily updates, under GPL-3.0.
- It is not native Surge syntax. It matches both validated WeChat PCDN hostnames and needs an independently verified conversion and exclusion plan.

### Decisions and next gates

1. Keep active full Advertising as the stable baseline. A prior No index problem with a different generated version does not alone prove current performance.
2. Evaluate actual app blocking and breakage before assigning a winner. Never publish private request logs to this public repository.
3. Create a deterministic fail-closed generator, license notices, exact exclusion tests and version-pinned candidate only after source selection.
4. Do not mistakenly convert StevenBlack exact HOSTS entries to suffix blocking. That silently changes semantics.
5. Current PR is research-only. No Advertising-Lite.list, no merge, no Surge or AdGuard Home changes.


## Third research round: broader Chinese and Surge-specific repositories (2026-11-23)

Read-only CI, **seven** measured candidates: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45180519754 (success). Baseline validation CI was also green. **No devices edited, no new output subscription.**

### Newly measured priority candidates

| Source | Source URL / format | Source content observed | Candidate simple domain predicates | Candidate domains matched by full Advertising | Candidate matches among four known-good domains |
| --- | --- | --- | ---: | ---: | --- |
| AWAvenue Pure Ads (native Surge RULE-SET) | https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/Filters/AWAvenue-Ads-Rule-Surge-RULE-SET-Only.Ads.list | 2026-11-23, 1.7.9, 19,110 bytes, 671 rules (643 DOMAIN, 11 DOMAIN-SUFFIX, 4 DOMAIN-KEYWORD, 13 IP-CIDR) | 651 unique | 361 | None via basic domain + keyword matching |
| DenzelVincent DNS mini (ABP-style) | https://github.com/DenzelVincent/adblock-dns-aggregator/blob/output/adguard/mini.txt | 2026-11-23, ~6,589 entries, 121,780 bytes in the CI snapshot, 1 line not recognized by simple parser | 6,588 unique simple | 5,861 | Both WeChat PCDN hostnames |

Notes:
- AWAvenue has four *intentional variants*: only ads, ads+privacy, ads+unwelcome, and all. "Unwelcome" includes PCDN, forced updates, push, and cloud controls. For this user's WeChat/SmartPay experience, **Only.Ads** is the meaningful baseline, not the default all-in-one list. AWAvenue also provides a distinct native Surge RULE-SET variant; do not mistake its domain-set version (dot-prefixed domains) for the RULE-SET variant.
- The exact native AWAvenue 671-rule file is licensed GPL-3.0. Its basic domain/keyword predicates did not match any of the four current known-good hostnames; this is NOT a guarantee against IP-CIDR, redirect, CNAME, or future rule risks. It covers just 62 of 290,391 existing full Advertising exact+suffix domain predicates in the conservative reverse check; switching would substantially reduce the static rule universe.
- The DNS mini aggregator imports AWAvenue **full** rules plus AdGuard Chinese in its mini tier (it is not equivalent to Pure Ads). This explains why it still contains both proven WeChat PCDN problem hostnames. It uses a sensible source manifest, threshold checks, allowlist-first filtering and reproducible output; its *approach* deserves consideration, but the 6.6k-domain output is not suitable for direct deployment unmodified. Its program code is MIT; generated content inherits its source licenses, including GPL-3.0.
- CI sample SHA-256: AWAvenue native 45cb8e7fc318765c85353c5ddfcabd216978288ba271de7f32e085a876319832; Denzel mini 5757ab9a54cb0cc7e621f0bb4ddd820053a89d2e79d93bbefe40ac59982eb033. Data are live snapshots, not frozen releases.

### Other inspected projects: borrow architecture, not their complete lists

| Project | Relevance | Main concern |
| --- | --- | --- |
| https://github.com/SukkaW/Surge | Exemplary whitelist management, separate DOMAIN-SET/non-IP/IP rules, clear ordering and REJECT variant design, well-described upstream provenance; active 2026-11-23 | Its published base advertising set is around 120k domain rules (extra ~90k); author expressly suggests Mac for this form of filtering and separate blockers on mobile. AGPL-3.0. Not "Lite" for our iPhone. |
| https://github.com/Cats-Team/AdRules | Chinese ads, HTTPDNS and PCDN coverage, multi-format output, explicit provenance (Source.md), Surge RULE-SET published | More than 210k DOMAIN-SUFFIX rules in the 2026-11-23 Surge output; intentionally blocks PCDN and HTTPDNS. Not an appropriate low-breakage base. Generated artifacts inherit source licenses even though scripts are 0BSD. |
| https://github.com/JiaDDD/SurgeRuleSet | Short conservative-source recipe (Loyalsoldier reject + Peter Lowe ad servers), daily native Surge generation, good as an audit inspiration | REJECT output lists over 200k entries, not lightweight. Relatively new and unproven for our known false positives; not a recommended replacement. |
| https://github.com/privacy-protection-tools/anti-AD | Mature China-oriented filter and clear "discretion" directory documenting intentionally controversial rules (including DNS) | That policy is already implicated in our WeChat DNS false positive. Borrow its disclosure method, not that domain decision. |
| https://github.com/belcheckyoung/Belcheck-QX-AdBlock | Real-traffic validation methodology, narrow ad-specific endpoints, app-by-app evidence, conservative fail-open handling when uncertain | Quantumult X-specific scripts/rewrites, not drop-in Surge domain list; README explicitly prohibits redistribution/mirroring, so only study principles, do not copy. |

### Revised engineering plan

**First candidate to prototype after separate authorization:** AWAvenue Pure Ads (native Surge 671 rules) as the small China-app advertisement core; examine a second independent, proven international ad/tracker baseline separately. Retain Privacy and Hijacking subscriptions at first to isolate the variable. Any AWAvenue-only trial must inspect 13 IP-CIDR entries and reject policy behavior on shared hosts, and verify known good connections and actual ad misses.

The goal is measured breakage vs ad-block tradeoffs and explainable per-category sources, **not** a target line count. Candidates cannot be merged or distributed as licensed third-party copied rules until their attribution/GPL conditions are met. Do not publish private Surge request logs. The initial draft PR should remain research-only.


## Fourth research round: compact international ad-only complement and IP-rule risk (2026-11-23)

Read-only nine-source audit: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45185218741 (comparison steps green). The study adds two *reference-only* candidates; **no subscription is published, no PR merged, and no device is changed**.

| Additional source | Unique exact HOSTS names | Matched by current Advertising | Outside current Advertising | Outside all Advertising / Privacy / Hijacking | Matches any four known-good domains |
| --- | ---: | ---: | ---: | ---: | --- |
| Peter Lowe source via StevenBlack's yoyo.org hosts mirror | 3,563 | 3,343 | 220 | 195 | No (exact-host check) |
| Peter Lowe official ads-only `notrackers=1` | 2,254 | 2,124 | 130 | 125 | No (exact-host check) |

- Original Peter Lowe source and inclusion policy: https://pgl.yoyo.org/as/ and https://pgl.yoyo.org/as/policy.php. Its `notrackers=1` mode excludes **entries tagged as trackers**, according to the maintainer's classification. It does *not* guarantee a pure DNS advertising list free of all privacy or malware-related entries.
- Official ads-only feed observed by CI: `https://pgl.yoyo.org/as/serverlist.php?hostformat=hosts&notrackers=1&showintro=0&mimetype=plaintext`; 58,521 bytes; SHA-256 `f1e3eaf111ed2840a4630b9a94f98169988eea5fde282fee62b610410879d1e5`.
- Full yoyo.org HOSTS mirror observed by CI: 88,220 bytes; SHA-256 `b3e7e62bca2058d8c6c20a41473f02cb5d76f5bc8854a04189071a042d42e56d`.
- The ads-only candidate is better aligned with a distinct Privacy RULE-SET already enabled. HOSTS are **exact** entries for this analysis; turning every HOSTS entry into `DOMAIN-SUFFIX` would significantly expand its effect and is not approved.
- The author-defined Peter Lowe categories are not a replacement for real-device functional tests or an exception list. The list's redistribution/license terms require clarification, even where a third-party mirror's code is permissively licensed.
- AWAvenue's 13 `IP-CIDR` rules were separately checked using Python's IP network parser: 13 IPv4, zero IPv6, zero reserved/private networks, zero prefixes broader than /24, zero invalid entries. This is **not** evidence that shared public IPs are safe to block. Prefer a domain-only initial prototype until each IP rule is independently justified.
- Keep all four already verified good hostnames as explicit fail-closed safety tests. Neither Peter Lowe candidate matches them under exact HOSTS semantics in this snapshot; AWAvenue's basic domain/keyword predicates also do not match them.
- Two-source experiment to evaluate, still **not authorized to publish**: AWAvenue `Only.Ads` native RULE-SET plus Peter Lowe official `notrackers=1` in exact-domain form, deduplicated by explicit DOMAIN and DOMAIN-SUFFIX coverage only. Report total sizes and static overlaps, then complete provenance/license and iPhone 15 Pro A/B checks before considering a replacement.

**Research interpretation:** Most of Peter Lowe's ads-only domains are already matched by the large current Advertising list. The reason to consider it is a small, curated international baseline with an explicit inclusion policy, **not** greater static blocking coverage. The combined pair's on-device effectiveness and latency have not been measured.
