# China_All / Privacy_All / Hijacking — read-only rule audit

> **Device-scope correction (2026-11-24):** The user confirmed that the spare iPhone 15 Pro uses a **separate iCloud account** from the primary iPhone Air. Therefore their Surge profiles do **not** cross-sync through iCloud. Earlier references in this report to a shared profile propagating to the primary iPhone were an incorrect precaution. Model-conditional DEVICE_MODEL rules on the spare are legacy safeguards and are not necessary to protect the primary device. This research modifies **only the connected spare**; the primary iPhone is not remotely accessible through this Surge controller.

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

**Overlap assessment update (superseded by subsequent full-list audits below):** the complete 39,936-rule Privacy file was fetched through Git Blob and compared with the fixed Lite snapshot. Exactly 86 / 2,890 Lite predicates are fully covered by Privacy. This is static rule coverage, not traffic overlap; keeping Privacy during A/B is still recommended.

## Hijacking: what it does and why it is not pure advertisement filtering

Hijacking is a small **known suspicious domain/IP and potential traffic hijack / spoof-domain** denylist. Its 185 suffixes include names resembling unofficial software download and publisher sites (`anydeskchina.cn`, `betterzipcn.com`), as well as 42 IPv4 prefixes. It also explicitly includes `DOMAIN,geo2.adobe.com`, illustrating that not every entry can be inferred to be a malicious hijacker by its hostname: some are telemetry or service-related, so independent classification is required.

A read-only actual Surge match for `geo2.adobe.com` returned `Hijacking.list` and REJECT, with local AdGuard Home also resolving the host to 0.0.0.0. **This is one data point, not evidence that the whole denylist is risk-free or that all IP ownership remains unchanged since 2025.**

Since the fixed-IP portion may age, review prefix ownership and false-positive records before mirroring or deleting any entries. Given only 228 entries, performance gains from trimming this set are likely negligible absent measurement.

## Recommendations and hold points

- **Keep all three current active rule sets unchanged during the Lite observation period.** Continue independently collecting specific false-positive hostnames, ideally with Surge rule-source and AdGuard Home DNS evidence.
- **Do not blindly merge Privacy + Hijacking + Lite.** Different provenance, purpose, update cadence, and false-positive risk. If future overlapping rules are removed, validate *effective* ordered matching and real app flows first.
- **China_All is a safer research target than an immediate deployment target.** Focus on its 9 keyword rules and 31 UA rules, potential redundant/malformed exact domains, and any material overseas service misrouting.
- **Privacy_All now has two independent large-file audit pipelines** with pinned snapshots and type-aware comparisons. These establish static rule coverage, not live traffic behavior.
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


## Round two: complete 39,936-rule coverage audit (2026-11-23)

GitHub's Git Blob API successfully delivered the full Privacy_All content even though its Contents interface had returned an empty payload. We parsed **all four pinned source snapshots** independently: Privacy_All 39,936 entries, Advertising Lite 2,890, Hijacking 228, and China_All 3,752. Public source rules were inspected in memory only and **were not copied into this repo**.

### Exact snapshot counts and rule types

| Snapshot | DOMAIN | DOMAIN-SUFFIX | DOMAIN-KEYWORD | IPv4 CIDR | IPv6 CIDR | USER-AGENT | Total |
|---|---:|---:|---:|---:|---:|---:|---:|
| Privacy_All | 19 | 39,897 | 9 | 11 | 0 | 0 | 39,936 |
| Advertising Lite | 2,875 | 11 | 4 | 0 | 0 | 0 | 2,890 |
| Hijacking | 1 | 185 | 0 | 42 | 0 | 0 | 228 |
| China_All | 17 | 3,674 | 9 | 17 | 4 | 31 | 3,752 |

Pinned Git blob identifiers (these are Git object hashes, not SHA-256):
- Privacy: a75df944a7a0fcae26f762059c0f7fd72f42c420
- Lite: ea6d2316d16180147930a363f928976a598d9431
- Hijacking: 0ffb798f0ce5f098fd3e7dc889fbbca94b9bdd5d
- China: bba28360d9dc0310b418df6d9fb7dfa76588c895

### Directional *full-rule coverage* (not traffic overlap)

The rule-coverage test counts A as covered by B only where **every destination matching a rule in A is also matched by B**. It handles domain exact matches, DNS suffix ancestors (with label boundaries), substring keyword implication and IPv4 CIDR subnet containment. It does not claim every partially intersecting rule is covered, and it does not know real blocked request frequency.

| Source → target | Fully covered source rules | Detail |
|---|---:|---|
| Lite → Privacy | **86 / 2,890 (2.98%)** | 83 exact-domain hosts by Privacy suffix, 2 by Privacy keyword, 1 identical exact |
| Privacy → Lite | **1 / 39,936 (0.0025%)** | Exact host js.users.51.la only |
| Hijacking → Privacy | **0 / 228** | None of the native predicates fully covered |
| Hijacking → Lite | **0 / 228** | None fully covered |
| Hijacking IPv4 ranges overlapping any Privacy IPv4 range | **0 / 42** | Based on the pinned lists |
| Hijacking suffix predicates fully covered by China_All | **64 / 185** | Mostly by broad .cn; NOT redundant, because policy REJECT conflicts with China Direct |

Examples: adjust.com, ads.linkedin.com, analytics.tiktok.com, adstats.tencentmusic.com and c2.gdt.qq.com are exact Lite domains covered by Privacy suffixes. Privacy keyword 'analytics.' covers the exact Lite hosts analytics.adjust.cn and analytics.rayjump.com. These are static matches, not user-traffic measurements.

The four explicitly allowed service hosts and all eight precautionary mini-program watchlist hosts did not match any domain/suffix/keyword predicate in Lite, Privacy or Hijacking. This static test cannot rule out AdGuard Home DNS sinkholing, changed upstreams, IP rules, or unknown functionality hosts. No live allowlist was changed.

### Hijacking findings requiring a human policy decision

- **Flash China:** The existing Hijacking rule directly blocks the entire flash.cn suffix. Adobe has publicly acknowledged an authorized China distribution relationship: https://community.adobe.com/announcements-637/update-on-flash-player-eol-719213 ; https://www.flash.cn/notice/notice?id=154 . A legitimate website can still be intentionally blocked for other reasons, but cannot be labeled malicious solely by list membership. **Do not unblock automatically.**
- **IP age and width:** Of 42 Hijacking IPv4 predicates, 40 are /32, one is 222.186.61.96/31 and one is 114.119.160.0/21 (2,048 addresses). The latter especially needs *current* ownership, shared-service, and reputation review before being retained or removed in a future curated list. Current WHOIS, ASN ownership and incident data have NOT yet been verified.
- Potential further functionality-policy review: geo2.adobe.com, mackeeper.com, newapi.com, anydeskchina.cn and betterzip.net. Flagged as ambiguous, not confirmed false positives.

### Recommendation and reproducibility

**Keep Privacy_All and Hijacking separately enabled during the current Advertising Lite device trial.** The large Privacy list supplies largely independent tracking controls and Hijacking has distinct predicates. Do not merge or delete them based on filename, rule count, or broad China overlaps.

New code: scripts/audit_privacy_hijacking.py; synthetic offline tests: tests/test_privacy_hijacking_audit.py; read-only GitHub Actions workflow: .github/workflows/research-privacy-hijacking.yml. It fetches only the pinned public Git blob bytes, validates Git-object SHA and expected type counts, and outputs aggregate statistics without publishing raw rule lists or user/device data.

**Important distinction:** the GitHub connector analysis independently established the above measurements; Actions workflow pass/fail must be validated from its actual run, not assumed merely because the workflow was added. PR remains DRAFT, no device changes, no main merge.


### Follow-up verification: CI and 114.119.160.0/21

**Automated verification PASS:** GitHub Actions run https://github.com/AutobotsRun/Surge-Rules/actions/runs/45202180764 completed successfully. Six focused unit tests passed, all four public Git blobs downloaded with pinned integrity checks, and the expected coverage counts and all 12 protected-domain checks were validated. The standard repository CI run https://github.com/AutobotsRun/Surge-Rules/actions/runs/45202180614 also passed. A small aggregate JSON-only artifact was uploaded; no list source, Surge profile or request traces were uploaded.

**Network identity of the widest Hijacking IP block:** Recent APNIC RDAP-derived records and public routing intelligence consistently associate 114.119.160.0/21 with Huawei Clouds in Singapore, AS136907, covering 2,048 addresses. Source references: https://whatismyip.live/whois/114.119.161.129 ; https://whoisrequest.com/ip/AS136907/114.119.160.0/21 ; https://www.ip2location.com/114.119.160.0 . This association does **not** establish that all 2,048 addresses have malicious behavior, nor that none do. Selected addresses in this prefix have been associated with PetalBot, Huawei's crawler: https://www.netify.ai/resources/ips/114.119.166.4 .

**Interpretation:** A cloud/crawler netblock appearing in a "Hijacking" denylist is another reason to categorize its actual purpose and user impact rather than call every IP a hijacker. Leave the existing rule unchanged during Lite observation; seek legitimate traffic evidence and policy intent before changing it.

## Third round: validated CI outcomes, security-function review and aged cloud IP range (2026-11-23)

## Third round: validated CI outcomes, security-function review and aged cloud IP range (2026-11-23)

### Independent workflow result verification

The second audit script and its independent CI checks completed successfully:

- Full pinned public Git-blob static audit: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45202180764 — **success**, 6/6 offline tests; its job validated 86/1/0/64 counts, checked twelve protected hosts and uploaded **only aggregate statistics**.
- Independent source comparison: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45202180632 — **success**, 7/7 offline tests.
- General repository validation: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45202180614 — **success**.
- Two read-only scripts are temporarily retained as **independent cross-checks**. They are not different lists. Consolidation can be considered once both test fixtures are preserved.

These assess *fixed source predicates*, not live user HTTP requests, real-device performance, RAM consumption or AdGuard Home DNS interception.

### Potential security-function false positive in Privacy_All

Fresh read-only Surge rule matches on the spare iPhone 15 Pro:

| Destination | Effective match | Outcome | Caveat |
|---|---|---|---|
| safebrowsing.googleapis.com | Privacy_All exact domain | REJECT | Google officially identifies it as a Safe Browsing API endpoint |
| safebrowsing.urlsec.qq.com | Privacy_All exact domain | REJECT | Also receives DNS 0.0.0.0; vendor role not independently verified |
| geo2.adobe.com | Hijacking exact domain | REJECT | AdGuard Home also supplies DNS 0.0.0.0 |
| www.microsoft.com | China_All broad microsoft keyword | Direct | Broad routing, not a reject |

Google documentation: https://developers.google.com/safe-browsing/reference/rest

**Risk qualification:** These Surge rules definitely match, but this does NOT prove that the user's installed Chrome, Safari or other apps call the Safe Browsing endpoint or that browser protections have failed. The Privacy rule predates the Lite experiment and **is not caused by Lite**. Confirm the calling app and account for independent AdGuard Home blocking before considering an allowlist exception.

### Hijacking broad IP block: current cloud infrastructure

The Hijacking list still contains IP-CIDR,114.119.160.0/21,no-resolve, a **2,048-address** block. Recent public prefix/ASN directories associate its origin with **AS136907 / HUAWEI CLOUDS**, including Singapore infrastructure:

- https://ipinfo.io/114.119.164.8
- https://whoisrequest.com/ip/AS136907/114.119.160.0/21
- https://httpsmonitor.com/asn/AS136907

An ASN route does NOT establish the reputation, tenant owner, or malicious/legitimate status of all IPs in the whole /21. Blocking a shared cloud prefix could create collateral damage; the old block may also still be justified. Require real app failure evidence and current IP reputation checks before changes.

The other broad rule, 222.186.61.96/31, covers two IPv4 addresses; the remaining forty IPv4 Hijacking rules are /32.

### flash.cn runtime nuance

Hijacking contains a flash.cn suffix predicate, intended to match the parent and all child hostnames. A fresh Surge match for flash.cn instead returned **DNS lookup failed / FINAL policy**, not Hijacking REJECT on that particular check. File membership and actual runtime match are not equivalent, especially when DNS fails.

### Decision

**Keep Privacy_All, Hijacking and China_All unchanged during the Advertising Lite trial.** Record Google Safe Browsing as a high-priority **separate compatibility investigation**, and the /21 prefix as a future **collateral-damage audit**. No new Direct exceptions or live profile changes are authorized by this review.


### Live Hijacking prefix match confirmation (no traffic generated)

On the spare iPhone 15 Pro, read-only Surge rule matching returned the following:

| Target IP | Matched rule | Decision |
|---|---|---|
| 114.119.160.1 | Hijacking IP-CIDR 114.119.160.0/21 | REJECT |
| 114.119.164.8 | Hijacking IP-CIDR 114.119.160.0/21 | REJECT |
| 114.119.167.254 | Hijacking IP-CIDR 114.119.160.0/21 | REJECT |
| 222.186.61.96 | Hijacking IP-CIDR 222.186.61.96/31 | REJECT |
| 222.186.61.97 | Hijacking IP-CIDR 222.186.61.96/31 | REJECT |
| 222.186.61.98 | GEOIP CN (does not match preceding Hijacking /31) | Direct |

This verifies actual Surge policy matching, but **does not establish whether real applications attempted to connect to those IPs**. The recent buffered request search for a hostname containing "safebrowsing" returned zero matches at inspection time; the buffer is limited and cannot prove no app ever uses those hosts.

No network packet was sent to any of the six IP targets; match_rule evaluates the active rule tree.


## Fourth round: browser Safe Browsing compatibility triage (2026-11-23)

**Scope:** No changes to Surge, iCloud profile, DNS, AdGuard Home or browser settings. Passive inspection and Surge rule evaluation only; PR remains Draft. The spare iPhone 15 Pro still uses home Wi-Fi and DNS 10.0.0.6.

### Public references

- Google identifies safebrowsing.googleapis.com as a real Safe Browsing API endpoint for URL/hash checks: https://developers.google.com/safe-browsing/reference/rest
- The separately documented Google OHTTP Safe Browsing Gateway API uses safebrowsingohttpgateway.googleapis.com: https://developers.google.com/safe-browsing/ohttp/reference . This does NOT prove that any given Chrome build calls the same host.
- Google documents privacy-preserving real-time checks for Chrome Standard Safe Browsing on iOS, mediated by a privacy server: https://security.googleblog.com/2024/03/blog-post.html and https://support.google.com/chrome/answer/13844634?co=GENIE.Platform%3DiOS&hl=en
- Safari has a separate Fraudulent Website Warning feature; its existence does not establish which back-end API host it uses on a given iPhone: https://support.apple.com/guide/iphone/browse-the-web-privately-iphb01fc3c85/27/ios

### Surge and DNS results

| Hostname | Verified Surge rule | DNS from 10.0.0.6 | Observed application request? |
|---|---|---|---|
| safebrowsing.googleapis.com | Privacy_All exact REJECT | 198.18.0.40 (fake-IP class; not 0.0.0.0) | Not in currently visible request buffer |
| safebrowsingohttpgateway.googleapis.com | Separately maintained Google service rule → US proxy | 198.18.12.35 (not sinkholed) | Not in currently visible request buffer |
| safebrowsing.urlsec.qq.com | Privacy_All exact REJECT | 0.0.0.0 (separate AdGuard Home DNS sinkhole) | Not in currently visible request buffer |

The fake-IP values are not the public remote server IPs and do not prove request success. The 0.0.0.0 result indicates network DNS blocking.

The Surge buffer is bounded (50 recent requests plus active connections). Case-insensitive filtering for safebrowsing, safebrowse, safebrowsingohttp, googleapis.com and urlsec.qq.com returned zero observed requests. The available Surge file log also contained no such hostname lines (288 retained lines at inspection). These are small and incomplete observation windows, NOT proof that installed browsers never use the services. Cached security decisions, different app modes, or privacy relays may also reduce visibility.

### Recommended non-destructive follow-up

1. Keep Lite, Privacy and Hijacking active; do not add a speculative broad allowlist.
2. If user wishes to validate Chrome iOS on the spare, first READ its Safe Browsing protection level in Chrome Settings, Privacy and security. Do not switch off protections.
3. Compare a controlled browser session on that device against Surge request logs. Browsing ordinary sites may not generate a visible safe-browsing API call; zero calls is not a successful functional test.
4. For functional warnings, use only a Google-owned Safe Browsing testing resource rather than real malicious websites, and NEVER bypass warning screens. This must be performed deliberately by the user if desired; no such test has occurred.
5. Only if specific functionality is demonstrably affected should an exact-host, spare-only temporary exception be considered; the Tencent host also needs separate AdGuard Home DNS analysis.

The independent pinned-source research script adds a security_endpoint_review classification with three hostnames and tests; this is NOT a production allowance or a service-reachability test.

**Conclusion:** Privacy may overblock an official Google security API, but there is still no evidence of lost Chrome or Safari protection. The OHTTP API hostname is not blocked by these three public rule sets and is eligible for the existing Google policy. No device configuration has been changed.


## Fifth round: single-domain Hijacking curation candidate (2026-11-23)

Adobe's current official network endpoint documentation explicitly lists **geo2.adobe.com**:
https://helpx.adobe.com/business/enterprise/manage-services/configure-services/network-endpoints.html

This establishes that the host can be legitimate Adobe app infrastructure, NOT a universally malicious hijack domain. We therefore prepared a **review-only test variant** of the pinned 228-rule Hijacking list with exactly one active predicate removed:

    DOMAIN,geo2.adobe.com

The candidate has **227 active rules** and preserves all 185 other suffix rules and all 42 CIDR rules, including 114.119.160.0/21. Its source comments, order and other rule bytes remain unchanged; it adds GPL-2.0 provenance and includes the existing bundled full GPL-2.0 license and a modification notice. This is only a proposed future filtering-policy correction, NOT an upstream repo update or an active Surge configuration.

- Generator: scripts/build_hijacking_curated_test.py, pinned public Git blob 0ffb798f0ce5f098fd3e7dc889fbbca94b9bdd5d.
- Offline regression tests: tests/test_hijacking_curated_test.py, 7/7 passed after correcting a test case that had accidentally searched comment text rather than active rule lines.
- [Independent builder and candidate diff CI — success](https://github.com/AutobotsRun/Surge-Rules/actions/runs/45207602555).
- [Repository validation — success](https://github.com/AutobotsRun/Surge-Rules/actions/runs/45207597695).
- Seven-day test archive: hijacking-curated-test-only-not-deployed (contains candidate list, manifest, GPL license and notices). No production upload, no live subscription, no DNS changes.

**Two-layer blocking matters:** Adobe geo2.adobe.com is also DNS-sinkholed by the user's local AdGuard Home (0.0.0.0). Merely removing it from Hijacking will **not** make it reachable at home. Any future functional fix requires a separate, evidence-supported DNS allowlist decision and A/B testing, not a blind worldwide domain exception.

**Next review topics, not deleted:** Tencent safety API hostname (blocked in Privacy and AdGuard DNS), wide historical 114.119.160.0/21 cloud prefix, and China_All keyword microsoft. No application-level failure has yet justified their removal.

This document and PR are review-only; nothing was deployed to the spare iPhone 15 Pro or the main iPhone Air.


## Sixth round: China_All predicate redundancy and real-route spot checks (2026-11-23)

**Source:** pinned, unchanged public China_All source Git blob bba28360d9dc0310b418df6d9fb7dfa76588c895 (3,752 rules).

### Truly redundant entries (without changing effective matching)

Using source type-aware static set containment, the audit found **45 / 3,752 (1.20%)** rules individually covered by OTHER existing rules of the same China set:

| Rule type | Redundant entries | Covering mechanism |
|---|---:|---|
| DOMAIN | 2 | Already covered by the broad microsoft keyword |
| DOMAIN-SUFFIX | 37 | Covered by existing keywords like alipay, aliyun, alicdn, baidu and microsoft |
| IPv4 IP-CIDR | 6 | Already enclosed by broader CIDR ranges with the same set policy |
| IPv6 IP-CIDR6 | 0 | No proven containment |
| Total | **45** | Source labels/policy must remain fixed |

The upstream generator already avoids individual .cn suffix entries because DOMAIN-SUFFIX,cn covers them: **zero** more-specific .cn suffix entries were found, so a previous assumption that there might be hundreds of such obvious duplicates was wrong.

The 45 predicates are strictly redundant **while their covering rules are retained**. It would be incorrect to remove the broad microsoft keyword *and* its covered domains without explicitly reinstating correct narrower routing. Do not equate syntactic redundancy with safe removal of a covering rule.

### Active device spot checks

Read-only Surge matching on the spare iPhone 15 Pro (all from China_All Direct):

- www.microsoft.com: DOMAIN-KEYWORD,microsoft
- login.microsoftonline.com: DOMAIN-KEYWORD,microsoft
- graph.microsoft.com: DOMAIN-KEYWORD,microsoft
- teams.microsoft.com: DOMAIN-KEYWORD,microsoft
- update.microsoft.com: DOMAIN-KEYWORD,microsoft
- www.microsoft365.com: DOMAIN-KEYWORD,microsoft
- azure.microsoft.com: DOMAIN-KEYWORD,microsoft

Unlike these, www.office.com and www.office365.com directly match independently listed .office.com and .office365.com suffix entries. Github.com matches FINAL/Smart rather than China_All.

This establishes **very broad effective direct-routing scope**, not a real network connectivity incident. No current Microsoft service regression was observed in recent requests, and Microsoft's globally distributed hostnames can legitimately be accessed direct or via a chosen proxy depending on user network policy. Do not delete the keyword in a live profile without targeted A/B.

### USER-AGENT capability caveat

31 USER-AGENT entries remain in China_All. Per Surge official iOS documentation, since iOS 15 the non-MITM HTTPS CONNECT User-Agent is unavailable: https://kb.nssurge.com/surge-knowledge-base/zh/technotes/user-agent . Thus these entries have limited effect for ordinary non-MITM HTTPS, but may still apply to other HTTP/MITM scenarios. **Not safe to label all 31 as dead rules**.

### Research follow-up

The existing scripts/audit_privacy_hijacking.py now also reports china_internal_redundancy, with a new synthetic regression test. Its read-only CI asserts exact source-pinned 45-rule redundancy by type, and does not alter or mirror the live China_All file.

**Priority:** Leave China_All active while awaiting the already identified Privacy main-app indexing test. Even after removing all 45 provably redundant entries, the size reduction is small and unproven to improve routing performance. The main value is independent review of overly broad keyword policy, not aggressive shaving of a relatively modest 3,752-rule set.

**No device configuration changes were made in this China audit.**

## Seventh round: verified 227-rule Hijacking spare-device cutover

**Device identity correction:** User confirmed the spare iPhone 15 Pro is on its own iCloud account, separate from the primary iPhone Air. Thus there is no cross-account iCloud sharing of Surge profile changes. Previous precautions about automatic propagation to the main phone were overconservative. The connected Surge MCP only controls the spare.

### Immutable staged source

- Experimental branch: experiment/hijacking-curated-20261124
- Pinned commit: 09a8434d829afdfce3583955d4173768a5b062ec
- Path: experiments/hijacking-curated/Hijacking-Curated-TEST.list
- Audited Git blob SHA: f1b234f38aaf6b4e0ff9eb97c941336444598da1
- Change: remove exactly DOMAIN,geo2.adobe.com from blackmatrix7's 228-rule GPL-2.0 Hijacking snapshot, resulting in 227. All other entries and order preserved.
- Attribution in test header and manifest; upstream GPL license in sources/blackmatrix7/LICENSE.

### Carefully staged live swap (verified)

1. Connected spare iPhone: staged the 227-rule curated candidate immediately before original Hijacking, with original kept unconditionally active as fallback.
2. Initial resource missing-file indication cleared after controlled resource refresh. Resource became ready=true with **no index error**. Unlike the large Privacy list, this small Hijacking rule-set indexed without needing a new main-app action.
3. Confirmed actual matches from the **candidate**, not old fallback: anydeskchina.cn REJECT; 114.119.164.8 REJECT via the unchanged /21; 222.186.61.96 REJECT via unchanged /31.
4. Removed only the old original Hijacking rule line from the spare profile. Preserved Advertising Lite, Privacy Curated, Google US and four WeChat/SmartPay Direct exceptions.
5. Final resource matrix: Hijacking-Curated-TEST.list, Privacy-Curated-TEST.list, Advertising-Lite-TEST.list and Google.list all **ready=true with no error**. Actual rule matches confirmed all retained protections above.

**Adobe nuance:** The legitimate Adobe host geo2.adobe.com no longer matches Hijacking, but local AdGuard Home DNS at 10.0.0.6 still replies 0.0.0.0. As a result, Surge reported a LAN Direct rule match (IP-CIDR,0.0.0.0/8). **This is a sinkhole side-effect, not evidence that Adobe access has been restored or that the host should be put on a DNS allowlist.** No AdGuard Home filter was changed.

**Rollback:** From the current spare's [Rule] section, replace only the curated Hijacking stanza with the previous exact original:
    # Hijacking
    RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Hijacking/Hijacking.list,REJECT
Then confirm geo2.adobe.com matches original Hijacking REJECT and other test cases match original. Do not alter Lite or Privacy.

**Status:** live rule-set cutover and representative rule matching verified; no claim of long-term Adobe or other app functional testing. PR #13 remains Draft, unrelated Google/DNS configuration unchanged.
