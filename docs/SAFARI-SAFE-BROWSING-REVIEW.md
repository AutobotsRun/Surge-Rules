# Safari Safe Browsing — Mainland China-compatible configuration proposal

**Final decision (2026-11-24): WITHDRAWN** — After reviewing Apple's Safari privacy disclosure, the user chose to **keep Tencent Safe Browsing blocked**. This supersedes every proposed Tencent exception or DNS allow step below. The owner accepts that Tencent-based Safari checks may not function; do not characterize this as full Safari protection. The single proposed Tencent AdGuard allow was **reverted from this research branch**, and the active main subscription still has the original four reviewed WeChat/payment allows only. The experimental 39,934-rule Safari file is **archived research, not the selected Privacy configuration**. On the spare iPhone, the extra Safari candidate was removed, the working 39,935-rule Privacy Curated reactivated, and live matching reconfirmed safebrowsing.urlsec.qq.com → Privacy REJECT, DNS 10.0.0.6 → 0.0.0.0, Google Safe Browsing → Google.list US, while Lite and Hijacking remained normal. PR #15 is being closed unmerged. Do not deploy this withdrawn proposal to the owner, spouse or spare.


**Status: RESEARCH / Draft only. Nothing in this PR is deployed.**

## Verified evidence

Apple's official Safari privacy disclosure (dated October 26, 2026) says Safari's enabled **Fraudulent Website Warning** may use **Google Safe Browsing and Apple**, and may additionally use **Tencent Safe Browsing** when the **device's Region** is set to China mainland or Hong Kong:

https://www.apple.com/legal/privacy/data/zh-cn/safari/

Apple says the full visited website URL is not shared with the Safe Browsing provider, but the external service may record a request IP. **Region is the device setting, not an Apple ID country.** Apple does not identify the exact hostnames for its Tencent requests or promise that each OS build uses a specific endpoint. Older network captures connect safebrowsing.urlsec.qq.com with Safari Safe Browsing, which is the host examined here:

https://hechen.github.io/post/%E5%85%B3%E4%BA%8E%E4%B8%80%E6%AC%A1-ss-%E6%B5%81%E9%87%8F%E4%B8%A2%E5%A4%B1%E7%9A%84%E8%BF%87%E7%A8%8B%E8%AE%B0%E5%BD%95/

On a **separate connected experimental iPhone** (NOT the intended Safari user's phone), read-only Surge checks show:

| Destination | Surge rule | Local DNS (10.0.0.6) |
|---|---|---|
| token.safebrowsing.apple | Apple.list → Direct | Non-sinkhole fake-IP reply |
| safebrowsing.googleapis.com | Google.list → US | Not sinkholed |
| safebrowsingohttpgateway.googleapis.com | Google.list → US | Not sinkholed |
| safebrowsing.urlsec.qq.com | Privacy-Curated REJECT | 0.0.0.0 sinkholed |

This proves two distinct filtering barriers on the **experimental phone only**. **It does not prove** a real Safari warning is broken on a different device. Other network security mechanisms may still function.

## Exact proposed changes, NOT active

1. Privacy curation: based on source-pinned blackmatrix7 Privacy_All, 39,936 rules, remove exactly TWO host REJECT predicates (Google and Tencent Safe Browsing), leaving 39,934 other original predicates and all comments/order unchanged. The Google host was already removed in the previously tested 39,935-rule variant; this proposal removes one ADDITIONAL Tencent host.
2. Retain the original matching order of service lists and China_All. With the exact Tencent deny gone, the existing China_All's .qq.com pattern is expected to route Tencent directly. The existing Google.list already routes the Google hostname, so neither service needs a redundant explicit exception in the final *curated-list* architecture.
3. In the same Draft PR, the AdGuard Home allowlist adds EXACTLY `@@||safebrowsing.urlsec.qq.com^` — no wildcard covering other Tencent services. Existing four payment/WeChat exceptions stay unchanged. **AdGuard Home DNS may need this second-layer change for actual connectivity.** Merely changing Surge routing will not override 0.0.0.0 DNS responses.
4. The new AdGuard allow applies **network-wide to clients using that AdGuard Home instance** if merged to the subscribed URL; it cannot be restricted to just a spouse's phone by this rule. Confirm whether that trade-off is acceptable before merging.
5. Current users maintain and share a *master Surge configuration manually*; experimental iPhone uses another iCloud account. **Do not claim a research-branch edit has changed the owner's primary or the family devices.** The spouse's actual Safari configuration and its DNS resolver have not been independently inspected.

## Automated fail-closed verification

- `experiments/privacy-curated/Privacy-Safari-TEST.list`: proposed 39,934-rule source snapshot, GPL-2.0 attribution; original upstream exact Git blob `a75df944a7a0fcae26f762059c0f7fd72f42c420`.
- `scripts/verify_safari_safebrowsing_candidate.py`: downloads the SHA-pinned original Git blob, verifies its Git-object SHA-1 digest, asserts byte-for-byte equality of the source body apart from exactly the two deleted active entries, checks exact original 39,936 / candidate 39,934 counts, original full GPL-2.0 license, and exactly five DNS allowlist exceptions.
- `.github/workflows/research-safari-safe-browsing.yml`: checks this from the pull request with `contents: read` and **no publishing or deployment**.
- The verified source for the existing Google.list includes DOMAIN-SUFFIX,googleapis.com.
- No changes to main branch, stable Surge service lists, existing DNS subscriptions, or a live network in this PR.

## Controlled evaluation after CI succeeds

First ensure the replacement 39,934-entry Privacy candidate can be indexed and actually matched by the experimental Surge device (large lists may require opening the iOS Surge main app). Check REJECT examples from the candidate and verify the exact Tencent host no longer matches the Privacy deny; **continue to observe independent AdGuard DNS behavior**. On any missing index, restore the current working 39,935-rule test and keep all other rules stable.

Do not disable Safari's Fraudulent Website Warning or visit actual malicious websites. If the network-wide DNS allowlist is later approved, first confirm using AdGuard Home Query Log that the hostname was blocked by a specific filter and that the precise allow takes effect. Verify both Wi-Fi and cellular scenarios: the DNS resolver can be different on mobile data. An allowed domain by itself proves connection policy, **not** that Safari phishing detection is fully functional. Finally update and manually share an audited *production* Surge profile, not a moving research branch.

## Rollback

- Privacy: restore the earlier tested pinned 39,935-rule Privacy Curated URL, with its existing status verified before switching.
- AdGuard Home: remove only the new exact Tencent allowlist line from its subscribed source (or disable that subscription change); check DNS Query Log after the next update.
- Leave Advertising Lite, Hijacking Curated, four known-good WeChat exceptions and China_All untouched.

**No change on the primary phone or any family member's phone should occur until the curated variant, resolver path, and Safari safety policy have been reviewed.**


## Live spare trial gate: pending main-app indexing (2026-11-24)

The source-pinned 39,934-rule candidate is now safely staged on the connected **spare iPhone 15 Pro only**, before the previously proven working 39,935-rule Privacy-Curated list. **The earlier list is still active as an unconditional fallback**, so the new candidate cannot silently remove tracking protection while its index is pending.

- Pinned URL: https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/4360b37499d7b73980e8b8dadd237715be5436ec/experiments/privacy-curated/Privacy-Safari-TEST.list
- The new resource refresh returned success. Its current status is ready=true **with error=No index** — this is NOT functional readiness.
- Actual tracking target analytics.strava.com still matches the older 39,935-rule Privacy-Curated REJECT (fallback); Tencent safebrowsing.urlsec.qq.com likewise still matches the older Privacy-Curated REJECT.
- Google Safe Browsing remains routed by Google.list to US. Advertising Lite and Hijacking Curated have not been changed.
- As with the previous large ruleset migration, the next action is to open the **Surge iOS main app on the spare** and verify the new on-disk index. Do not disable any ad blocking, DNS protection or Safari security warning.
- We will retire the old Privacy fallback only after the new list is error-free and demonstrably matches retained tracking domains. **DNS allow from the Draft PR remains UNMERGED and AdGuard Home remains unchanged.**
- No real-world Safari unsafe-website warning test has been performed. The connected device is not the Safari user's phone.

**No claim that Tencent Safari access has been restored.** The old Privacy fallback continues to deny it and home DNS still returns 0.0.0.0 until the separate proposed DNS choice is reviewed.
