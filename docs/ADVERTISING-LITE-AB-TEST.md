# Advertising Lite — spare iPhone A/B runbook (research only)

Status: Experimental. Draft PR artifact only. No public production subscription or live phone change.

## Confirmed and unconfirmed

- On 2026-11-23 the user confirmed the existing full Advertising profile and AdGuard Home allowlist worked for the WeChat mini-program and its previously affected payment page.
- The 2,890-rule Lite artifact passed 23 offline tests and a GitHub Actions export: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45191084044
- Not yet confirmed: whether Surge iOS successfully loads the Lite file, live coverage, performance, or functional correctness.

## Guardrails

1. The main iPhone Air stays unchanged. Use the spare iPhone 15 Pro only.
2. Export and preserve the spare device's working profile before making changes.
3. The connected Surge controller has not been identified as the spare iPhone. Do not make any remote edits without positively confirming that device identity.
4. Keep Wi-Fi/DNS/AdGuard Home, Privacy, Hijacking, WeChat routing, modules, policy groups and proxy nodes unchanged throughout A and B.
5. Home AdGuard Home may sinkhole WeChat resource hostnames independent of Surge, so do not claim a Surge-only cause from a DNS rejection.

## Collect the test file

Open https://github.com/AutobotsRun/Surge-Rules/actions/runs/45191084044 and download the artifact named advertising-lite-surge-test-only (retention: 7 days). It contains four files:

- Advertising-Lite-TEST.list (Surge external RULE-SET)
- LICENSE.GPL-3.0.txt
- THIRD_PARTY_NOTICES.md
- manifest.json

Verify that the full-file SHA256 for Advertising-Lite-TEST.list equals the manifest value:

    240347ee54b5baee112535ea647a8cce4878bba5b971924072066bdedf8ed0a7

The 2,890-rule canonical digest differs from the full-file SHA because the latter includes attribution comments.

## Phase A: Full-list baseline on spare

Keep the original full Advertising rule and make sure four verified-good exact Direct rules are **persistent** and **above the Advertising REJECT rule**:

    DOMAIN,apd-pcdnwxlogin.teg.tencent-cloud.net,"🚀 Direct"
    DOMAIN,apd-pcdnwxstat.teg.tencent-cloud.net,"🚀 Direct"
    DOMAIN,dns.weixin.qq.com.cn,"🚀 Direct"
    DOMAIN,smartpay-admin.fugetech.com,"🚀 Direct"

Check that the actual policy name on the spare is 🚀 Direct. The main phone had two of these as **runtime temporary overrides**, which can disappear if Surge stops. The AdGuard Home allowlist is separate and must stay intact.

Use the validated WeChat mini-program and payment page; do not make an actual payment just for testing. Also compare WeChat messages, official-account images and video, common apps, and known ad placements. Record user-visible results separately from connection errors.

## Phase B: Lite on spare ONLY

Using the spare phone's Surge local RULE-SET file import, locate Advertising-Lite-TEST.list and replace exactly **one** original rule line:

    RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/01d9fb3132a75680441e01fa06b6a7d46fd69059/rules/Advertising.list,REJECT

with a RULE-SET reference to the exact imported local file; the following is a **nonfunctional placeholder**, not a line to paste literally:

    RULE-SET,<actual-local-file-path>/Advertising-Lite-TEST.list,REJECT

**Never keep both full and Lite Advertising rules enabled together.** Retain the same four Direct exceptions above this rule, and unchanged Privacy and Hijacking below.

First check Surge has loaded the 2,890-rule external file with no skipped-line warnings, and check the four known-good domains. If it fails to parse, immediately restore the full rule profile. Only after successful parsing, repeat the same app flows on the **same spare phone** under the **same network conditions**.

## Phase C: Review and restore

Restore the spare profile to full Advertising at the end, regardless of results. Compare actual missed ads and broken features, not only rule counts: Surge uses compact domain indexes, so 291k vs 2.9k does not imply a 100x speedup.

Stop immediately on failed login, mini-program resources, Tencent/WeChat DNS, payment page, repeated TLS failures, or unexpected blank assets. Check Surge and AdGuard Home independently before attributing a blockage. Keep private request traces off public GitHub issues.

References:
- Surge rule set syntax: https://manual.nssurge.com/rules/ruleset.html
- GPL and source attributions: THIRD_PARTY_NOTICES.md in the artifact
- Research details: docs/ADVERTISING-LITE-RESEARCH.md

This is a runbook only. No A/B trial was performed, no device was modified, and the research PR remains draft.
