# Safe Browsing privacy-filter exception — controlled spare-device fix

**Date:** 2026-11-23. **Status:** A targeted live change was explicitly authorized by the user. This documentation-only PR does not deploy the change or merge any lists. Keep it Draft.

## Why

The upstream `Privacy_All.list` from `blackmatrix7/ios_rule_script` contains the exact rule `DOMAIN,safebrowsing.googleapis.com`. It is currently loaded as `REJECT`, *before* the user's service-specific Google rules. Surge verified that it was actually selected on the spare iPhone 15 Pro.

Google identifies this address as the legitimate Google Safe Browsing API service endpoint:
https://developers.google.com/safe-browsing/reference/rest

The user explicitly confirmed Chrome iOS's **Standard protection** is enabled and authorized removal of inappropriate copied third-party rules. Google says Standard protection includes privacy-preserving, privacy-server-mediated URL checks:
https://support.google.com/chrome/answer/9890866?co=GENIE.Platform%3DiOS&hl=en

A blocked API may interfere with third-party apps that call this service; it does **not**, by itself, establish that the user actually lost Chrome or Safari protection. No risky-site browsing tests were attempted.

## Exactly what changed on the spare iPhone

Connected Surge iOS controller independently identifies the spare iPhone 15 Pro as `DEVICE_MODEL=iPhone16,1`. Its shared profile is under an iCloud Drive synced directory, so edits can synchronize profile *text* to other devices. We therefore **only enabled this exception for iPhone16,1** using official Surge conditional syntax.

Added in the profile's existing `[Rule]` section immediately before `# Privacy` and the upstream Privacy REJECT rule:

```ini
# Security service exception: preserve official Google Safe Browsing API on spare iPhone only.
#!REQUIREMENT DEVICE_MODEL=='iPhone16,1' DOMAIN,safebrowsing.googleapis.com,"🇺🇸 US"
```

This is a higher-priority exact destination rule, not a removal from the original third-party subscription, which we do not control. The effective outcome is that the legitimate Google API is **no longer rejected on the spare**. It routes using the existing US policy, consistent with other Google services. `Privacy_All` is still active for every other entry. Other device models still use their previous policy for this API until separately reviewed.

**Why not edit upstream:** A remote third-party RULE-SET cannot be safely modified line-by-line; removing this entry literally would require a separately hosted, license-compliant curated fork and carefully staged switch. The precise override is the lower-risk correction during the current Lite comparison.

## Evidence after the change (read-only Surge checks)

| Target | Actual effective policy | Result |
|---|---|---|
| safebrowsing.googleapis.com | `🇺🇸 US` | **Changed** from Privacy REJECT to an exact permitted route |
| safebrowsingohttpgateway.googleapis.com | `🇺🇸 US` (existing Google list) | Unchanged |
| safebrowsing.urlsec.qq.com | Privacy `REJECT` | Unchanged; independent AdGuard Home DNS sinkhole `0.0.0.0` remains |
| ad.qq.com | Lite `REJECT` | Unchanged; 2,890-rule Lite continues working |
| pagead2.googlesyndication.com | Lite `REJECT` | Unchanged |
| smartpay-admin.fugetech.com | `🚀 Direct` | Unchanged |
| dns.weixin.qq.com.cn | `🚀 Direct` | Unchanged |
| geo2.adobe.com | Hijacking `REJECT` | Unchanged |
| www.microsoft.com | China_All `🚀 Direct` | Unchanged |

`Advertising-Lite-TEST.list`, Privacy_All and Hijacking external resource states remained **ready=true** after the profile reload. No new AdGuard Home rules or GitHub production `rules/` files were modified; the browser's Standard protection setting was not changed.

## Potential further cleanup (not applied)

- `safebrowsing.urlsec.qq.com`: name suggests a Tencent-related safety function and is blocked both in Privacy and by AdGuard Home DNS. Without authoritative service ownership/use evidence or verified client requests, **do not silently bypass both layers**.
- `geo2.adobe.com`: Adobe officially lists it as a necessary network endpoint in its Adobe-app endpoint documentation:
  https://helpx.adobe.com/business/enterprise/manage-services/configure-services/network-endpoints.html
  It is in Hijacking and is DNS-sinkholed by AdGuard Home, so a Surge-only allow rule would not restore functionality. Investigate actual device/app need and network-wide consequences before touching DNS.
- `114.119.160.0/21`: Hijacking blocks 2,048 addresses currently associated with Huawei cloud infrastructure. Blocking a shared cloud subnet may be overbroad, but do not unilaterally delete on ownership evidence alone; check actual failures first.
- `DOMAIN-KEYWORD,microsoft`: currently directs even `www.microsoft.com` via China_All. Broad routing deserves targeted review, not automatic removal.

## Exact rollback

On the spare device's shared `[Rule]` text, remove only the new comment and conditional exact-host rule above. Surge reverts that destination to Privacy_All `REJECT`. Leave the original Advertising Lite/full conditional setup, four known-good WeChat Direct rules, and all other rules unchanged.

**Important:** Surge warns that UI edits may lose `#!REQUIREMENT` expressions. Preserve the condition annotations if making any later UI edits to this iCloud-synchronized profile:
https://manual.nssurge.com/profile/requirement.html

Research-only context: https://github.com/AutobotsRun/Surge-Rules/pull/13

This document records a user-approved, reversible change already applied through Surge MCP. The PR itself **does not deploy or apply** device edits.


## Follow-up: why Google service catalog alone is insufficient (2026-11-23)

User suggested placing the exact Safe Browsing exception inside the self-maintained Google rule collection. This is conceptually correct but redundant at source:

- The existing 703-rule managed Google list already includes DOMAIN-SUFFIX,googleapis.com, which covers the official Safe Browsing API host.
- The active Surge profile evaluates Privacy_All REJECT before Google.list US. Surge matches the first applicable rule, so moving the Safe Browsing entry into Google.list alone would not restore access.
- Moving the whole Google list before Privacy is potentially unsafe: comparing the 703-rule Google list with the pinned 39,936-rule Privacy finds seven Google suffix root domains affected by Privacy matching, including Google Analytics and Google Tag Manager. Reordering may bypass deliberate tracking suppression.
- The existing spare-iPhone priority exception already uses the same US policy as normal Google services. No immediate device change is needed.

### Staged future clean architecture (not yet deployed)

After Lite observation, use a curated Privacy variant with exactly one deletion and allow the existing later Google list to route this host. Remove the priority exception at the same time; it is no longer needed once Privacy does not block that host. Do not add a redundant exact host to Google.list.

- Generator: scripts/build_privacy_curated_test.py, pinned upstream Git blob a75df944a7a0fcae26f762059c0f7fd72f42c420.
- Scope: original 39,936 Privacy predicates minus DOMAIN,safebrowsing.googleapis.com = 39,935; all other rule lines and upstream comments remain byte-identical.
- Attribution: GPL-2.0, existing full license file and modification notice in generated ZIP.
- Validation: 8 of 8 offline tests passed and a public source verification plus single-delta comparison succeeded in CI: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45206819953 .
- Repo validation also succeeded: https://github.com/AutobotsRun/Surge-Rules/actions/runs/45206819916 .
- TEST-ONLY 7-day workflow artifact: privacy-curated-test-only-not-deployed (Privacy-Curated-TEST.list, manifest.json, LICENSE.GPL-2.0.txt, THIRD_PARTY_NOTICES.md).
- Permissions of research workflow: contents read only. No normal rules files were replaced and there was no deploy.

### Planned switch checks (after current Lite testing)

1. Back up the iCloud-synchronized profile. Verify the device is the spare iPhone16,1; preserve the old Privacy list for all other device models.
2. Supply the curated candidate using a pinned immutable test URL verified on-device, and keep it in the existing Privacy position. Do not activate the old and new Privacy REJECT lists together.
3. Only after the new resource is ready, remove the now-redundant earlier Safe Browsing exception on the spare. Confirm Google's existing googleapis.com route selects US.
4. Retest Lite ads, WeChat payment Direct exceptions, remaining Privacy tracking and the Tencent safety domain; verify effective per-host matches and ensure original Privacy remains on other devices.
5. If any regression appears, revert the single Privacy switch and restore the original one-line priority exception.

No curated Privacy source is deployed. The current spare-device Safe Browsing exception remains active.

## Attempted Privacy test and verified rollback (2026-11-23)

The user authorized a staged Privacy trial. A fixed, audited GPL-2.0 experiment snapshot was published on a separate experimental branch, never on main:
- Branch: experiment/privacy-curated-20261123
- Pinned commit: ed558890190af404456b7ca5d68ac119cd087566
- Path: experiments/privacy-curated/Privacy-Curated-TEST.list
- Candidate blob SHA: 71485074a103d11998a75432ad7566833a97657f
- Diff: exactly one deleted Privacy DOMAIN rule, 39,936 to 39,935.
- Independent legal attribution: source GPL license exists at sources/blackmatrix7/LICENSE, with branch-level THIRD_PARTY_NOTICES.md and manifest.json.
- A HEAD probe to the small manifest returned HTTP 200; a probe to the large 1.44 MB list failed at the probe's response-content-size limit, unrelated to rule syntax.

### Trial and safety

1. Added a model-conditional RULE-SET in the existing Privacy location, selecting only iPhone16,1, while the original Privacy was conditionally retained for all other device models. The earlier Google Safe Browsing explicit exception remained.
2. The new resource initially showed a missing-file status; the Surge refresh action reported success.
3. The new resource then showed ready=true **but also error=No index**. Rule matching for analytics.strava.com and the Tencent Safe Browsing service fell through to China, confirming the new Privacy index was NOT effective. We did not infer success from ready alone.
4. **Immediately rolled back the entire test Privacy stanza** to the exact previous original Privacy line. The section revision returned to its original value, with all other Rule content and the Live Advertising Lite preserved.
5. After rollback, original Privacy appeared ready=true; analytics.strava.com and safebrowsing.urlsec.qq.com again matched the original Privacy REJECT. The exact Google Safe Browsing exception still routed US and ad.qq.com still matched Lite REJECT. No production data or other devices were changed.

The persistent Surge log explicitly states:

    Index not found: .../Privacy-Curated-TEST.list. Please open the main app to complete indexing.

Surge official rule-set documentation notes that external lists with >1000 domain entries use a disk-backed index:
https://manual.nssurge.com/rules/ruleset.html

**This is an index-creation prerequisite, not proof of invalid test file content.** The third-party resource is not yet usable from the Surge background extension alone.

### Next safe test when the user is able to open the spare iPhone's Surge main app

- Keep original Privacy enabled as fallback **on the spare too**, instead of removing it until the curated candidate's index is verified. Place the curated test before the original in ordered rules.
- Leave the existing Google Safe Browsing exact exception unchanged during index creation.
- Have the user open Surge on the spare so main-app indexing can finish.
- Only when match_rule shows the new candidate actively blocking normal tracking domains and there is no No index error, remove the original Privacy for the spare (while keeping it on other models).
- After further verification remove the now redundant Google Safe Browsing exact exception and confirm its normal route through Google.list (which already has DOMAIN-SUFFIX,googleapis.com).
- Any failure: restore the original Privacy and retain all other rules unchanged.

**Current status:** the original Privacy works and the candidate is **not deployed**. No loss of protection remains from the attempted test. No successful live curated-Privacy test is claimed.


## Current protected preload state (awaiting main-app index)

We staged the already-published pinned experimental Privacy RULE-SET as **first** Privacy rule for iPhone16,1, while leaving original Privacy_All **unconditionally active as its immediate fallback on all devices**. This explicitly addresses the failed-index window discovered earlier, with no need for the user to weaken tracking protection.

The relevant current profile stanza is:

    # Privacy
    # SPARE-IP15PRO-PRIVACY-PRELOAD: curated first; keep ORIGINAL as always-active fallback until index verified.
    #!REQUIREMENT DEVICE_MODEL=='iPhone16,1' RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/ed558890190af404456b7ca5d68ac119cd087566/experiments/privacy-curated/Privacy-Curated-TEST.list,REJECT
    RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Privacy/Privacy_All.list,REJECT

Verified real Surge matches after staging:
- Candidate: listed ready=true, but error=No index. **Not yet effective**.
- Original Privacy_All: listed ready=true. analytics.strava.com and safebrowsing.urlsec.qq.com → original Privacy REJECT.
- Prior priority Safe Browsing Google US exception and Lite ad REJECT still active.
- The main iPhone Air and other model devices still use the original Privacy_All and do not activate candidate because of model condition.

**Current user step:** open the Surge main iOS app on the spare iPhone 15 Pro so the downloaded external RULE-SET can complete its on-disk indexing. There is no need to turn off VPN, browse unsafe websites, reset configurations or modify the main iPhone.

**Next assistant verification once user has opened the main app:** check resource No index has disappeared and analytics.strava.com is REJECT by Privacy-Curated-TEST.list itself rather than the old fallback; then explicitly decide whether to retire the fallback on spare only and remove the redundant Google exception. Do not treat ready=true without matching proof as success.

**Do not assume the user has opened Surge or that indexing has completed.**
