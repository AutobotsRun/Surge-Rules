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
