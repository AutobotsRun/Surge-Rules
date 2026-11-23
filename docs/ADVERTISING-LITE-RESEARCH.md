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
