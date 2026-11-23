# China_All / Privacy_All / Hijacking — read-only rule audit

**Date:** 2026-11-23. **Status:** Research only, no changes to live Surge, iCloud profile, AdGuard Home, Apple devices, production rules, or subscription URLs.

## Context and rule order

The connected Surge iOS 6.0.1 device (spare iPhone 15 Pro, experiment on Advertising Lite) has the following relevant order in its active `[Rule]` section:

1. Conditional Advertising Lite REJECT on the spare phone (full Advertising remains the conditional choice for other devices).
2. `Privacy_All.list,REJECT`
3. `Hijacking.list,REJECT`
4. `China_All.list,"🚀 Direct"`
5. Later service RULE-SET lines, local LAN and GEOIP CN, then FINAL.

**Important:** Actual ordered profile contains some other service routes as well. Surge's first matched rule wins; an earlier Privacy or Hijacking REJECT prevents a later China direct rule from taking effect. The country rules are not a substitute for ad and tracking protection.

## Sources and sizes

All three rule sets are from blackmatrix7/ios_rule_script under its GPL-2.0 project, not authored by the user.

| Current active public source | Upstream `UPDATED` header | Declared entries | Breakdown |
|---|---|---:|---|
| `rule/Surge/China/China_All.list` | 2026-06-22 02:36:19 | 3,752 | 17 DOMAIN, 3,674 DOMAIN-SUFFIX, 9 DOMAIN-KEYWORD, 17 IPv4 CIDR, 4 IPv6 CIDR, 31 USER-AGENT |
| `rule/Surge/Privacy/Privacy_All.list` | 2025-12-08 02:06:16 | 39,936 | 19 DOMAIN, 39,897 DOMAIN-SUFFIX, 9 DOMAIN-KEYWORD, 11 IPv4 CIDR |
| `rule/Surge/Hijacking/Hijacking.list` | 2025-06-06 09:15:02 | 228 | 1 DOMAIN, 185 DOMAIN-SUFFIX, 42 IPv4 CIDR |

The `UPDATED` field denotes the upstream generated list's header date, **not** evidence of a repository outage or a current automatic update failure.

For China and Hijacking, complete contents were fetched via the GitHub connector, and parser counts matched their headers. In the first round, the oversized Privacy_All file could not be read through GitHub's contents API. In the **second round it was successfully fetched in full through GitHub's Git Blob API**, and all four pinned public sources were compared by a tested offline Python script. The observations below under 'Second round' supersede the initial incomplete state. Static rule entailment is not a measurement of traffic volume or blocking effectiveness.

Upstream refs:
- https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Surge/China/README.md
- https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Surge/Privacy/README.md
- https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Surge/Hijacking/README.md

Git blob SHA at review: China `bba28360d9dc0310b418df6d9fb7dfa76588c895`; Hijacking `0ffb798f0ce5f098fd3e7dc889fbbca94b9bdd5d`. These are source object identifiers, **not** SHA-256 integrity hashes or the commit hashes of the whole repository.

## China_All audit findings

**Purpose:** routing domestic service domains and IPs to direct transport. This is categorically different from a REJECT list. Cutting it arbitrarily may send normal domestic apps via offshore proxies.

1. **One broad suffix controls enormous traffic:** `DOMAIN-SUFFIX,cn`. A read-only actual rule match for `some-unlisted-service.cn` selected China_All and Direct because of the generic `.cn` suffix. Rule **entry count alone greatly understates behavioral coverage**.
2. **Broad keyword `DOMAIN-KEYWORD,microsoft` affects overseas domains.** Direct Surge match of `www.microsoft.com` selected China_All / Direct by this predicate. That may or may not be desirable; domestic routing should be tested per service rather than deduced from keyword.
3. The other eight native China keyword predicates are: `.tmall.com`, `alicdn`, `alipay`, `aliyun`, `baidu`, `beplay`, `officecdn`, and `taobao`. Broad substring rules deserve case-by-case review for false routing, not automatic removal.
4. There are **31 USER-AGENT** entries, such as `MicroMessenger*`, `QQ*`, `Microsoft*`, and `WeChat*`. According to the Surge Knowledge Base, iOS 15+ normally suppresses the CONNECT User-Agent for HTTPS requests when MITM is not used for those hosts. Thus the effectiveness of these entries is context-dependent and often limited on modern iOS; do not treat them as guaranteed per-app routing.
5. China_All contains `DOMAIN,analytics.strava.com`, but the actual effective rule match for this domain returned **Privacy_All REJECT** via `DOMAIN-KEYWORD,analytics.` (AdGuard Home also returns `0.0.0.0` for this name). The earlier Privacy rule wins. **An entry in China does not imply Direct in the running profile**.
6. Another suspicious exact entry is `origin-a.akamaihd.ne` (without the final `t`), adjacent to `origin-a.akamaihd.net`. Flag for review only; do not modify upstream or production without confirming whether it has valid intended use.
7. The user has no observed urgent functional failures attributable to this list. The full China_All rule count, only 3,752, is not by itself a compelling reason to strip or clone it immediately.

Read-only matched examples from spare device:
- `some-unlisted-service.cn` → China_All `DOMAIN-SUFFIX,cn` → Direct.
- `www.microsoft.com` → China_All `DOMAIN-KEYWORD,microsoft` → Direct.
- `www.google.com` → user's earlier service-specific Google rules → US proxy.
- `github.com` → FINAL Smart proxy.
- `analytics.strava.com` → Privacy_All `DOMAIN-KEYWORD,analytics.` → REJECT.

## Privacy_All: what it does and why it may overlap Lite

Privacy_All is a **tracking / telemetry / user-behavior blocking** list, not an all-purpose network privacy guarantee. Rules may suppress telemetry requests even where there is no visible advertisement. A specific verified example is `DOMAIN-KEYWORD,analytics.`, which currently REJECTs `analytics.strava.com`. There are likely functional edge cases: apps may use analytics and other subdomains for shared initialization, troubleshooting or other features. Blocklisting alone neither encrypts connections nor prevents every form of data collection.

**Overlap assessment status:** unknown for the complete sets. We have not computed exact or semantic coverage intersections with the 2,890-rule Lite candidate. Never remove Privacy solely because Advertising Lite was successfully loaded, especially while conducting its A/B trial.

## Hijacking: what it does and why it is not pure advertisement filtering

Hijacking is a small **known suspicious domain/IP and potential traffic hijack / spoof-domain** denylist. Its 185 suffixes include names resembling unofficial software download and publisher sites (`anydeskchina.cn`, `betterzipcn.com`), as well as 42 IPv4 prefixes. It also explicitly includes `DOMAIN,geo2.adobe.com`, illustrating that not every entry can be inferred to be a malicious hijacker by its hostname: some are telemetry or service-related, so independent classification is required.

A read-only actual Surge match for `geo2.adobe.com` returned `Hijacking.list` and REJECT, with local AdGuard Home also resolving the host to 0.0.0.0. **This is one data point, not evidence that the whole denylist is risk-free or that all IP ownership remains unchanged since 2025.**

Since the fixed-IP portion may age, review prefix ownership and false-positive records before mirroring or deleting any entries. Given only 228 entries, performance gains from trimming this set are likely negligible absent measurement.

## Recommendations and hold points

- **Keep all three current active rule sets unchanged during the Lite observation period.** Continue independently collecting specific false-positive hostnames, ideally with Surge rule-source and AdGuard Home DNS evidence.
- **Do not blindly merge Privacy + Hijacking + Lite.** Different provenance, purpose, update cadence, and false-positive risk. If future overlapping rules are removed, validate *effective* ordered matching and real app flows first.
- **China_All is a safer research target than an immediate deployment target.** Focus on its 9 keyword rules and 31 UA rules, potential redundant/malformed exact domains, and any material overseas service misrouting.
- **Privacy_All requires a separate large-file audit pipeline** for complete set overlap, source pinning, and type-aware intersection. Avoid claims based solely on its count.
- **Hijacking can be individually reviewed in a small offline audit** of 186 hostname predicates plus 42 IP entries; prioritize stale IP/CIDR validity, ambiguous publisher/Adobe entries.
- Only after observation and evidence would we propose a new fixed-commit, license-compliant alternative with separate rollback. No production policy or service rules were changed in this audit.

Official technical references:
- https://manual.nssurge.com/rules/overview.html
- https://manual.nssurge.com/rules/ruleset.html
- https://kb.nssurge.com/surge-knowledge-base/zh/technotes/user-agent

This is an analytical report. It includes no private profile text, proxy credentials, private request logs, or client identifiers.


## Second round: complete source-pinned overlap calculation (2026-11-23)

**Reproducibility:** A separate 4-source reader was added at scripts/audit_privacy_lite_overlap.py, with tests/test_privacy_lite_overlap_audit.py and read-only workflow .github/workflows/research-privacy-lite-overlap.yml.

- Workflow success: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45200996871
- General repo validation success: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45200996232
- **7/7 offline tests** passed; the four sources' actual Git-blob SHA-1 objects and expected counts were checked before comparison.
- CI artifact: surge-privacy-lite-overlap-readonly (aggregate JSON only; no copied third-party blocklists, private network logs or profile contents).

### Four audited source sizes

| List | Rules | Relevant types |
|---|---:|---|
| Lite pinned experimental file | 2,890 | 2,875 DOMAIN, 11 DOMAIN-SUFFIX, 4 DOMAIN-KEYWORD |
| Privacy_All | 39,936 | 19 DOMAIN, 39,897 DOMAIN-SUFFIX, 9 DOMAIN-KEYWORD, 11 IP-CIDR |
| Hijacking | 228 | 1 DOMAIN, 185 DOMAIN-SUFFIX, 42 IP-CIDR |
| China_All | 3,752 | 17 DOMAIN, 3,674 DOMAIN-SUFFIX, 9 DOMAIN-KEYWORD, 17 IPv4, 4 IPv6, 31 USER-AGENT |

### Predicate entailment results (NOT request-level overlap)

Here **fully covered** means *every hostname* that matches the subject DOMAIN, DOMAIN-SUFFIX or DOMAIN-KEYWORD predicate must also match at least one reference predicate. This is stricter than the two lists sharing some hosts. To avoid false conclusions, IP-CIDR and USER-AGENT comparisons, actual request frequencies, DNS pre-matching and policy evaluation order are **excluded** from the overlap percentages.

| Subject rules | Already fully covered by | Count | How |
|---|---|---:|---|
| Lite (2,890) | Privacy | **86 / 2,890 = 2.98%** | 1 exact DOMAIN, 83 covered by Privacy suffixes, 2 covered by Privacy keywords |
| Privacy (39,936) | Lite | **1 / 39,936 = 0.0025%** | one exact DOMAIN: js.users.51.la |
| Lite | Hijacking | **2** | 2 Lite exact domains covered by Hijacking suffix predicates |
| Hijacking | Lite + Privacy together | **0** | Domain predicate containment only; no evaluated IP containment |
| China_All (3,752) | Privacy | **7** | 5 covered by suffixes, 2 covered by Privacy keywords |

The only **textually identical same-type same-value** Lite/Privacy rule is DOMAIN,js.users.51.la. The 86 counted above include the more general Privacy suffixes and keywords, not 86 identical lines. A different weighting by actual traffic could give completely different percentages.

The seven China entries fully covered by Privacy are:
- DOMAIN,analytics.strava.com
- DOMAIN-SUFFIX,cmpassport.com
- DOMAIN-SUFFIX,giocdn.com
- DOMAIN-SUFFIX,growingio.com
- DOMAIN-SUFFIX,irs01.com
- DOMAIN-SUFFIX,rtbasia.com
- DOMAIN-SUFFIX,volceapplog.com

Because Privacy REJECT appears before China Direct in the user's rule order, these domain predicates are effectively shadowed, but precise runtime behavior still depends on other earlier rules and DNS.

### Potential security-function false positive: Safe Browsing

The complete Privacy file includes exact DOMAIN rules for:
- safebrowsing.googleapis.com
- safebrowsing.urlsec.qq.com

**Verified on actual spare iPhone 15 Pro:** safebrowsing.googleapis.com matches Privacy_All REJECT, independent of the Lite rule. Google's official API service documentation confirms that this is a real Safe Browsing service used by clients to check malicious/phishing URLs:
https://developers.google.com/safe-browsing/reference/rest

This raises a legitimate **security-function compatibility concern**, not proof that any particular installed browser lacks protection. Implementations may use different endpoints, local databases or platform services. The Tencent URL-security hostname is also a manual review candidate; do not assert it is used by a specific device until corroborated.

The original Hijacking list additionally includes DOMAIN,geo2.adobe.com, and 42 IP-CIDR rules (40 /32, one /31 and one 114.119.160.0/21). The /21 can match a range of 2,048 IP addresses. This is not automatically unsafe, but its ownership and current threat justification deserve more review given the 2025-06 upstream generated date.

### Known-good domains and priority

The four user-confirmed functional hostnames:
- apd-pcdnwxlogin.teg.tencent-cloud.net
- apd-pcdnwxstat.teg.tencent-cloud.net
- dns.weixin.qq.com.cn
- smartpay-admin.fugetech.com

are **not statically matched** by any of the audited Lite, Privacy or Hijacking domain predicates. This is a domain-rule audit, not a guarantee against AdGuard Home independent DNS filtering or IP-range rules.

**Current recommendation (no device change):** Keep Lite + Privacy + Hijacking separated for now. Mark Safe Browsing endpoints for manual functional verification before any change; prioritize the unusual 114.119.160.0/21 IP range and Adobe host for Hijacking evidence review. China keyword microsoft remains overbroad enough to warrant separate route-specific testing. Source-pinned snapshots are preferable to unknown moving master revisions once future changes are approved.

At the time of writing this report, **zero** profile lines, active Surge modules, AdGuard Home allowlists, default branch rules, and subscribed services were changed by this research round. Both Lite and this independent research PR remain in their previously stated states.
