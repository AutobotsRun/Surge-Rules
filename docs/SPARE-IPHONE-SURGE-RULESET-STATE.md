# Verified spare iPhone 15 Pro Surge rule-set state

**Snapshot date:** 2026-11-24. **Scope:** the connected spare iPhone 15 Pro (Surge iOS 6.0.1) only. The user's primary iPhone Air uses a **separate Apple Account / iCloud account**, so the two Surge profiles do **not** auto-sync through iCloud.

This is a sanitized audit snapshot of the advertising, privacy and network safety portions of the spare's Rule section, **not** the whole private profile. It contains no proxy credentials, private hostnames, or internal network topology. GitHub PRs #12/#13/#14 remain draft. Upstream sources and output rules are pinned to Git commit snapshots rather than floating research branches.

## Current effective policy order

Before these rule sets, the profile has its existing private home-service/local policy (not reproduced here). The following block is active in the spare's [Rule] section:

```ini
# Advertising
# INDEPENDENT SPARE IPHONE: four proven WeChat/payment Direct exceptions + Advertising Lite
DOMAIN,apd-pcdnwxlogin.teg.tencent-cloud.net,"🚀 Direct"
DOMAIN,apd-pcdnwxstat.teg.tencent-cloud.net,"🚀 Direct"
DOMAIN,dns.weixin.qq.com.cn,"🚀 Direct"
DOMAIN,smartpay-admin.fugetech.com,"🚀 Direct"
RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/41cc017763ae9ef2127eac28be1effd11ef1080e/experiments/advertising-lite/Advertising-Lite-TEST.list,REJECT

# Privacy
# INDEPENDENT SPARE IPHONE: reviewed one-rule curated Privacy
RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/ed558890190af404456b7ca5d68ac119cd087566/experiments/privacy-curated/Privacy-Curated-TEST.list,REJECT

# Hijacking
# HIJACKING-CURATED-TEST: one Adobe service predicate removed; all other 227 rules preserved.
RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/09a8434d829afdfce3583955d4173768a5b062ec/experiments/hijacking-curated/Hijacking-Curated-TEST.list,REJECT

# China
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/China/China_All.list,"🚀 Direct"
```

Other later service-rule groups, Google list routing, and the original local/final rules remain in their existing order and are not recopied into this document.

**Important behavior:** No early exact-host safebrowsing.googleapis.com override remains. Because the Privacy-Curated source removes precisely the original upstream REJECT for that exact host, the existing Google.list DOMAIN-SUFFIX,googleapis.com naturally routes it through 🇺🇸 US, without adding or moving the Google list.

The old **291,173-rule full Advertising** and **39,936-rule original Privacy** alternatives have been removed from this **spare's** Rule section only. No DEVICE_MODEL condition remains, because the spare uses a separate iCloud account and does not share its Surge file with the primary iPhone. The primary device's configuration was neither read nor modified by this controller.

## Test result matrix

| Source or host | Observed on spare | Rule path |
|---|---|---|
| Advertising Lite | 2,890 rules; ready=true, no error | Experiment subscription |
| Privacy Curated | 39,935 rules; ready=true, no error | Experiment subscription |
| Hijacking Curated | 227 rules; ready=true, no error | Experiment subscription |
| ad.qq.com / pagead2.googlesyndication.com | REJECT | Lite |
| analytics.strava.com | REJECT | Privacy Curated |
| safebrowsing.urlsec.qq.com | REJECT | Privacy Curated and still DNS-sinkholed by AdGuard Home |
| safebrowsing.googleapis.com | 🇺🇸 US | Existing Google.list |
| anydeskchina.cn | REJECT | Hijacking Curated |
| 114.119.164.8 | REJECT | Hijacking Curated's original /21 prefix |
| Four WeChat/SmartPay exceptions | Direct | Four exact domain rules before Lite |
| www.microsoft.com | Direct | Original China_All keyword |
| geo2.adobe.com | no longer a Hijacking REJECT; Surge selected LAN Direct | **AdGuard Home still returns 0.0.0.0**, so this does NOT prove Adobe service access |

These are rule engine checks and resource status checks. They are not long-term observed app-functional-success data, and none should be interpreted as an allowlist expansion in AdGuard Home.

## Rollback strategy

On the spare only, change **one rule set at a time**, read the current [Rule] revision and apply optimistic concurrency:

- Advertising Lite → previous original full-list fixed URL `https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/01d9fb3132a75680441e01fa06b6a7d46fd69059/rules/Advertising.list`, preserving the four known-good Direct exceptions.
- Privacy Curated → the upstream original `https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Privacy/Privacy_All.list`; if Google Safe Browsing service is still required on the spare, restore the exact early Google policy override before that original REJECT list.
- Hijacking Curated → original `https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Hijacking/Hijacking.list`.
- Leave China_All and AdGuard Home unchanged unless separately reviewed and explicitly verified.

Always check actual match_rule results **and** external-resource index errors before declaring success. In particular, the first large Privacy trial showed that ready=true can coexist with No index until the iOS Surge main app builds the on-disk index.

## Further research, not deployed

- The Microsoft keyword in China_All makes even global Microsoft identity and Graph domains route Direct. Regional endpoint distinctions are documented by Microsoft, but no replacement route has passed A/B.
- Apple says Safari may use Tencent Safe Browsing for devices with mainland China or Hong Kong set under **Settings > General > Language & Region**, not based on iCloud account region. The exact Tencent hostname remains blocked in the current Privacy list and in AdGuard Home DNS; relaxing that is a **privacy versus anti-phishing protection trade-off** that has not been decided.
- Hijacking's legacy 114.119.160.0/21 block covers 2,048 IPs currently routed by Huawei Cloud Singapore; ASN ownership does not establish individual IP safety.
- These third-party GPL-2.0 experimental variants have original license attribution and change notices in the research repository. Do not silently merge research PRs or replace them with moving source URLs before review.
