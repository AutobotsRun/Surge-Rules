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

### Verified two-source deduplication (offline model)

Run: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45185449367 (success; 8/8 research tests).

| Quantity | Observed |
| --- | ---: |
| AWAvenue Only.Ads native rules | 671 |
| Peter Lowe ads-only exact HOSTS domains | 2,254 |
| Peter Lowe domains already covered by AWAvenue DOMAIN / DOMAIN-SUFFIX | 14 |
| New exact DOMAIN rules from Peter Lowe after deduplication | 2,240 |
| **Modeled combined native RULE-SET size, retaining 13 AWAvenue IP-CIDR rules** | **2,911** |
| **Modeled combined size, omitting those 13 IP-CIDR rules for first-phase safety** | **2,898** |

All four proven-good hostnames returned *no match* under the tested combined domain / keyword predicates. This does **not** evaluate IP resolution against the 13 public-IP rules or real requests; the 2,898-rule calculation is only a structural candidate, not a generated, tested, licensed, or published output. A smaller list may simplify auditing, but the Surge rule-set engine already indexes large domain sets, so do **not** claim demonstrated speed, memory, or battery improvements without a device benchmark (official rule-set documentation: https://manual.nssurge.com/rules/ruleset.html).

**Next gate:** review the four native DOMAIN-KEYWORD predicates, verify Peter Lowe list redistribution permission, add a deterministic exact-host conversion with source acknowledgement, run Surge-compatible parsing and known-good tests, then do a reversible A/B on the spare iPhone 15 Pro only. Keep main iPhone Air on its existing production rules.


## Fifth research round: source semantics, keyword/IP and functional-endpoint safety (2026-11-23)

CI evidence: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45186929275 (12/12 research unit tests; read-only source comparison succeeded). Repo-wide validation also succeeded: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45186929262.

### Licensing and author intent

- Peter Lowe's own homepage, https://pgl.yoyo.org/as/, explicitly invites users to **combine the list with other lists and publish the combination** (in the paragraph beginning "Feel free to combine"). It is explicit permission for that described use, not a published standard license that we can assume covers *every* type of sublicensing or warranty. Prominent credit and a live source link should accompany any eventual derived publication.
- The AWAvenue Only.Ads file links its GNU GPL-3.0 license (https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/LICENSE). Before publishing a derived mixed list, preserve original provenance, relevant GPL notices and copyright, include GPL license text or a compliant route to it, and mark modifications. Do not describe a blended artifact as "MIT" or as wholly original.
- Peter Lowe's inclusion policy https://pgl.yoyo.org/as/policy.php includes **ad servers, trackers, malware, anti-adblock and other undesirable hosts**. Its notrackers=1 setting removes entries explicitly tagged as trackers, not necessarily every non-advertising category. Therefore **"ads-only" describes the feed parameter, not a verified strict content taxonomy**.
- The Peter Lowe maintainer specifically favors entries at the highest suitable adserver domain and notes that DNS-zone blocking may cover all its subdomains. A HOSTS-to-exact-DOMAIN translation is conservative **but may underblock** relative to the intended DNS use. Blind HOSTS-to-DOMAIN-SUFFIX conversion is broader and can introduce false positives. Keep both semantics distinct.

### Modelled semantic alternatives

Source snapshot: AWAvenue native Only.Ads 671 rules and Peter Lowe official notrackers=1 2,254 HOSTS entries.

| Modeled conversion for Peter Lowe | Already covered by AWAvenue under that exact rule semantics | Peter Lowe rules newly included | Total including 13 original IP rules | Total with 13 original IP rules omitted |
| --- | ---: | ---: | ---: | ---: |
| Conservative exact DOMAIN | 14 | 2,240 | 2,911 | **2,898** |
| Broad DOMAIN-SUFFIX | 1 | 2,253 | 2,924 | **2,911** |

Suffix-mode deduplication correctly requires existing DOMAIN-SUFFIX coverage. An existing exact DOMAIN rule alone cannot justify deduplicating a prospective suffix entry. These numbers are structural estimates only; a suffix is not equivalent to a single exact host even when line counts are similar. Both simulations passed four known-good hostname checks, but a simulated successful domain check is **not** evidence of IP, CNAME or live traffic safety. Neither model has been exported or published.

### Native AWAvenue detailed safety review

The four exact native keyword tokens are: \`-ad.sm.cn\`, \`-ad.video.yximgs.com\`, \`-ad.wtzw.com\`, and \`-be-pack-sign.pglstatp-toutiao.com\`. All are longer, host-shaped ad identifiers, which is more constrained than a generic token such as \`ad\`. They still use **substring matching anywhere in the host** and must remain individually reviewable; no claim of zero false positives.

All 13 AWAvenue IP-CIDR entries in the audited source are global IPv4 \`/32\` and carry \`no-resolve\`; none is IPv6, broader than /24, syntactically invalid or missing the flag. This reduces unnecessary hostname DNS lookups but does not guarantee safe blocking of potentially shared IP addresses. **Exclude the 13 from any first-stage experimental derivative until real service/IP ownership analysis.**

A manual-review watchlist identifies **eight native exact rules** plausibly associated with functionality rather than solely third-party ads (unverified false-positive risks; no automatic removal or positive/negative categorization in this research PR):

- \`wxa.wxs.qq.com\`
- \`wximg.wxs.qq.com\`
- \`wxsmw.wxs.qq.com\`
- \`wxaintpcos.wxqcloud.qq.com.cn\`
- \`hybrid.miniapp.taobao.com\`
- \`mini-prog-drm.vodplayvideo.net\`
- \`pay.sboot.cn\`
- \`sdkconfig.video.qq.com\`

These names are public upstream rules, not user request-log observations. Our four locally tested domains do **not** exhaust possible false positives. A first A/B should require explicit review/exclusion decisions for the watchlist, especially the WeChat mini-program endpoints, before enabling REJECT.

### Automated safety additions (read-only)

- Enumerates keyword tokens and the eight potential functional-domain flags in statistics.
- Validates IP family, prefix, global/public ranges, syntax and \`no-resolve\` usage.
- Models exact and suffix conversion **separately**.
- Refuses any proposed-pair simulation if either mode collides with the four verified-good hostnames.
- Includes tests that intentionally make suffix expansion hit a known-good subdomain and verifies the analysis fails closed, plus a limited catastrophic-public-suffix guard.
- **Caution:** the short hardcoded dangerous-suffix guard is *not* a Public Suffix List replacement; a real published generator must use a maintained PSL, manually reviewed suffix promotions, and strict source-format checks.

### Next gate before any actual Advertising-Lite.list

Build a reproducible, testable **non-deploying** preview compiler with pinned hashes and required exact exceptions, leaving AWAvenue functional-domain candidates and the 13 IP entries excluded pending manual review. Start with exact Peter Lowe domain semantics; permit explicit suffix promotions only after individual review. Produce source/license notices, SHA-256, and private/test-only artifacts; never expose third-party raw lists or private Surge logs in public GitHub Actions. Final device A/B must be on spare iPhone 15 Pro only, while the main iPhone Air and existing production URLs stay unchanged.

**Status: PR #12 remains draft research, not a new subscription.**


## Sixth research round: reproducible non-deploying Lite preview (2026-11-23)

**Result:** https://github.com/AutobotsRun/Surge-Rules/actions/runs/45187623797 succeeded. 19 research/preview unit tests passed, as did source comparison and the memory-only preview step. The ordinary repo validation run https://github.com/AutobotsRun/Surge-Rules/actions/runs/45187623618 succeeded.

New files:
- \`scripts/preview_advertising_lite.py\`: strict source reader, pinned-source SHA-256 verification, explicit exact HOSTS -> DOMAIN mapping, native-rule semantics retained, protected functionality checks. Outputs **JSON counts and digest only**, writes **no rule file**.
- \`tests/test_advertising_lite_preview.py\`: offline fail-closed tests for source format, known-good domains, functional-domain quarantine, IP omission, deterministic results, keyword scope and suffix hazards.
- \`.github/workflows/research-advertising-lite.yml\`: now runs all 19 Lite tests and a metadata-only preview alongside its nine-source analysis. Public CI artifacts contain statistical JSON only, not third-party rule contents.

### Exact-hosts safety-first in-memory preview

| Measurement | Verified count |
| --- | ---: |
| AWAvenue native Only.Ads incoming | 671 |
| Original IP-CIDR rules omitted pending review | 13 |
| Potential functional exact host rules quarantined | 8 |
| AWAvenue native rules retained | **650** |
| Peter Lowe official \`notrackers=1\` HOSTS total | 2,254 |
| Peter Lowe exact domains newly included after semantic deduplication | **2,240** |
| **Preview rules in memory** | **2,890** |
| Known-good exact/suffix/keyword conflicts | 0 |
| Eight functional-review-domain conflicts after quarantine | 0 |

Canonical deterministic in-memory sorted-line digest: \`92cdd3dd0eed603d9eb153fed92b06ef8dd9d21ef949df883ac29c098ffdf632\`. It is a **preview digest** and not a published file or a Surge-verified parser artifact.

Source pins from the audited public snapshots:
- AWAvenue Only.Ads SHA-256: \`45cb8e7fc318765c85353c5ddfcabd216978288ba271de7f32e085a876319832\`
- Peter Lowe official \`notrackers=1\` SHA-256: \`f1e3eaf111ed2840a4630b9a94f98169988eea5fde282fee62b610410879d1e5\`

The preview intentionally **fails closed** if either upstream updates or the parser sees an unknown structure. Refreshing a source requires reviewing its actual diff and explicitly updating the source pin. Nothing silently changes on a phone.

Remaining cautions:
1. HOSTS-to-exact-DOMAIN underblocks descendant ad hosts relative to Peter Lowe's higher-level DNS-zone blocking intent; future suffix promotions must be separately audited. The preliminary 2,924-rule all-suffix alternative is **not** a safe deployable candidate.
2. The eight quarantined exact hosts are plausible functional endpoints based on naming, not confirmed false positives. Their exclusion is an experimental safety precaution, not an upstream correction.
3. Quarantining exact hostnames and checking four locally verified services cannot guarantee no other breakage. The source includes other Tencent/WeChat, payment, CDN and app-resource names that still warrant app-by-app validation.
4. Licensing/source-notice work and Surge parsing on real iOS remain mandatory before publishing. The private iPhone 15 Pro A/B must replace, not stack, the active Advertising subscription; save the original URL for immediate rollback. The primary iPhone Air remains untouched.
5. **No \`rules/Advertising-Lite.list\` exists; nothing has been merged; no devices, AdGuard Home filters, or active subscription URLs were modified.**


## Seventh research round: real-device WeChat baseline observation (2026-11-23)

This is a **production full Advertising baseline**, **NOT a Lite test**. Only an anonymous, aggregate interpretation is recorded here; no raw Surge network requests, private request URLs, device identifiers, payment records, or captured bodies are published.

- The active Surge configuration still uses the pinned full Advertising RULE-SET. The user opened their previously problematic WeChat mini-program flow for a baseline check. The user has **now explicitly confirmed the tested WeChat mini-program flow and previously problematic payment page worked normally**. This is a successful user-confirmed functional baseline (without initiating a real payment), alongside non-failing observed network requests. It does **not** validate the Lite candidate.
- Surge had **six active Direct connections** to the previously approved payment-related hostname, none carrying a reported connection failure; at least some had transferred data in both directions.
- Observed related WeChat resource domains routed Direct without reported errors. A WeChat gateway-report host instead followed a Hong Kong proxy via FINAL; it likewise had non-failing connection observations. This different routing may be worth separately studying but does not itself prove malfunction.
- The two exact-domain overrides for the known payment administrator and WeChat DNS service were **runtime temporary rules** (not persistent profile rules). Their working state cannot be assumed to survive stopping the Surge engine, and the eventual rollback/persistence plan must distinguish these overrides from independently maintained AdGuard Home allowlist entries.
- The local DNS resolver/AdGuard Home independently returned 0.0.0.0 for several publicly listed Tencent/WeChat resource hostnames. Replacing a Surge-only Advertising RULE-SET would not necessarily unblock requests already sinkholed upstream. A/B methodology must keep resolver filtering constant and isolate the component under test.
- This observation supports retaining the exact known-good exception tests and quarantining ambiguous mini-program endpoints in the Lite study; it does not demonstrate Lite compatibility, reduced breakage, advertising coverage, or faster matching.
- **No payment initiated by the assistant, no Surge/AdGuard modifications, no public request dump.** Keep PR in draft research state until explicit real-device Lite validation is possible.


## Eighth research round: offline test-only export with notices (2026-11-23)

- Checked the official Surge external RULE-SET format at https://manual.nssurge.com/rules/ruleset.html. The candidate mixes DOMAIN, DOMAIN-SUFFIX and DOMAIN-KEYWORD, so it is **not** a DOMAIN-SET. Surge silently skips invalid lines with a warning, so CI must strictly lint every generated line.
- Checked Peter Lowe's explicit permission to combine and publish (https://pgl.yoyo.org/as/) and AWAvenue's GNU GPL-3.0 license (https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/LICENSE).
- Added exporter scripts/export_advertising_lite_test_artifact.py and four focused offline tests. The exporter checks both pinned upstream SHA-256 values, strict source/rule syntax, count=2,890, exact canonical digest, the 13-IP exclusion count, eight quarantined hosts, and full upstream GPL license availability. Every artifact has attribution/provenance, modification disclosures, actual license text, and a JSON manifest.
- **Live CI:** https://github.com/AutobotsRun/Surge-Rules/actions/runs/45191084044 succeeded, **23/23 unit tests** passed, export succeeded, and draft-only artifact upload succeeded. Standard repo validation https://github.com/AutobotsRun/Surge-Rules/actions/runs/45191084059 succeeded.
- The draft-PR-only Actions artifact is **advertising-lite-surge-test-only**, expires after seven days, and contains Advertising-Lite-TEST.list, LICENSE.GPL-3.0.txt, THIRD_PARTY_NOTICES.md, and manifest.json.
- Full file SHA-256 (including attribution comment header): 240347ee54b5baee112535ea647a8cce4878bba5b971924072066bdedf8ed0a7
- Canonical 2,890 rule-line SHA-256 (without header): 92cdd3dd0eed603d9eb153fed92b06ef8dd9d21ef949df883ac29c098ffdf632
- Added docs/ADVERTISING-LITE-AB-TEST.md: spare iPhone 15 Pro only, stable primary untouched, persist known-good Direct exceptions, compare separate full vs Lite phases **without stacking**, account for AdGuard Home DNS interference, verify Surge loading and restore the original profile.
- No file was committed under rules/ or default branch. The Actions artifact is **not a public raw URL**, a live subscription, or proof of Surge/iOS compatibility. A/B remains unperformed pending controlled local import on the spare device.

Previous notes saying there is "no list exported" describe the earlier **memory-only preview** stage; the later **test-only Actions artifact** now contains a generated .list, but remains outside the repo's live rule catalog.


## Ninth round: spare-iPhone conditional deployment and direct rule matching (2026-11-23)

User explicitly requested changing Surge. Surge iOS script environment independently confirmed DEVICE_MODEL=iPhone16,1, matching the user's spare iPhone 15 Pro; Surge version 6.0.1. The existing Surge.conf was in iCloud Drive Shadow; edits may be uploaded to iCloud immediately, so a naive unconditional full-list replacement was not performed.

### Pinned experimental resource

The checked and GPL-attributed draft-only export bundle (2,890 entries) was published once to the research branch under experiments/advertising-lite with LICENSE.GPL-3.0.txt, THIRD_PARTY_NOTICES.md and manifest.json. Pinned immutable test URL:

    https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/41cc017763ae9ef2127eac28be1effd11ef1080e/experiments/advertising-lite/Advertising-Lite-TEST.list

It returned HTTP 200 to Surge before loading. The original verified file SHA-256: 240347ee54b5baee112535ea647a8cce4878bba5b971924072066bdedf8ed0a7. The one-time GitHub Actions publication block was then removed and its permission reverted to contents: read.

### Conditional rules in the iCloud-shared Rule section

Official device-specific syntax: https://manual.nssurge.com/profile/requirement.html

- Only DEVICE_MODEL=='iPhone16,1' gets four persistent known-good exact Direct exceptions and the new Lite RULE-SET.
- Every other model is intended to retain the original full Advertising RULE-SET via an end-of-line requirement DEVICE_MODEL!='iPhone16,1'. The original rule line remains in the shared profile; its end-of-line requirement format is backward-compatible with older Surge builds that treat the requirement as an ordinary comment.
- Privacy, Hijacking and all unrelated profile sections are retained unchanged. This is a change to a potentially iCloud-synced profile document, but the conditional rule semantics are intended to preserve primary-device behavior.
- The user's iPhone Air was **not** directly connected to or tested, so its actual effective state has not been independently verified.

### Observed on spare device

- The initial external resource showed not-ready / file-not-found, so a resource refresh was invoked before interpreting any match results. Refresh succeeded and now the external Lite resource is ready=true. The full Advertising external resource is absent on the spare.
- Direct matched Lite RULE-SET with the precise source subrules for ad.qq.com and pagead2.googlesyndication.com; both REJECT.
- Each of the four known-good service hostnames now matched the persistent exact Direct rule.
- Removed two duplicated runtime temporary Direct rules for payment and WeChat DNS; both remain Direct afterward, confirming permanent exceptions are active. No temporary rules remain.
- Some other domain checks were rejected by DNS sinkhole 0.0.0.0 and built-in LAN/China effects; those observations are **not** proof of Lite coverage and must not be treated as such.

### Still pending

The actual WeChat mini-program/payment-page and other apps have NOT been retested with Lite, nor has performance been benchmarked. No default branch merge. The research PR stays draft, and the test list does not replace the normal rules/ catalog. The primary iPhone Air may see the shared profile text via iCloud; no rule editing should be done in Surge's UI while the test depends on requirement annotations, because some UI paths can remove such expressions.

Rollback: In the shared Rule section, remove the five experiment-only DEVICE_MODEL=='iPhone16,1' rules (four Direct and one Lite RULE-SET) plus experiment comment; strip the end-of-line DEVICE_MODEL!='iPhone16,1' requirement from the original full Advertising rule, leaving it unqualified. No other changes required.
