# Curated rule sets: release candidate 2026.11.24-rc1

**Review only; no production deployment.** The owner has reported normal day-to-day testing on the designated spare iPhone. The overnight VPN stop remains unexplained; the iOS Jetsam report supplied by the owner identified SpringBoard and Widgets rather than a Surge termination. Do not claim this release resolves that incident or guarantees long-term stability.

## Release scope

| File | Active predicates | Effective changes vs live spare |
| --- | ---: | --- |
| rules/Advertising-Lite.list | 2,890 | 0 |
| rules/Privacy.list | 39,935 | 0 |
| rules/Hijacking.list | 227 | 0 |

All predicate sequences were compared with immutable tested artifacts and read back from GitHub. [Manifest](../config/curated-rules-release.json) records the source and candidate Git blob hashes. [License and modifications](CURATED-RULES-NOTICES.md) are preserved.

The previous full Advertising.list is untouched. China_All stays original; Microsoft routing stays Direct. Google Safe Browsing remains under existing Google.list; Tencent Safe Browsing remains blocked in Privacy and existing DNS filtering, per the owner's explicit decision (withdrawn PR #15). No change to AdGuard Home, the four DNS allows, other services, modules, scripts, or device configurations.

## After review and merge

1. Validate candidate rules using a fixed commit SHA, then manually advance stable after approval. Use stable/rules/ for ongoing subscriptions, not main. The old Privacy-Curated.list and Hijacking-Curated.list paths are retained as compatibility aliases and must not be subscribed alongside their replacements.
2. Switch one rule-set at a time on the spare, retaining the current immutable experimental subscription as a fallback until the new file indexes and real match tests pass. For large Privacy, open the main Surge app if the resource reports No index. Remove the fallback after verification; never leave duplicate lists running.
3. Validate normal ad and tracker rejects, the two retained Hijacking IP examples, Google US, Tencent REJECT, the four existing direct exceptions and Microsoft Direct. A rule-match check alone is not an app compatibility test.
4. After successful spare-device review, the owner may manually update the master profile and share it with family. No automatic deployment or iCloud transfer to those devices.
5. For rollback, replace only the affected new release URL with its tested_commit/tested_path in the manifest. The separate full Advertising option remains available at its previously reviewed pin. Do not combine both ad lists or change DNS to compensate for a rule-set problem.

The existing research PRs #12, #13 and #14 are historical reference and source code, not intended to be merged wholesale; #15 is withdrawn. This release does not change the existing upstream monitoring catalog or schedule. Future changes require new reviewed source fingerprints, deterministic output and tests; update the manifest only with a reviewed release.

## Policy template (existing ordering, placeholders are intentional)

Keep the four exact Direct exceptions before Advertising. Use existing profile policy names. This is not a complete profile and contains no private credentials.

```ini
# Advertising
DOMAIN,apd-pcdnwxlogin.teg.tencent-cloud.net,"🚀 Direct"
DOMAIN,apd-pcdnwxstat.teg.tencent-cloud.net,"🚀 Direct"
DOMAIN,dns.weixin.qq.com.cn,"🚀 Direct"
DOMAIN,smartpay-admin.fugetech.com,"🚀 Direct"
RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/stable/rules/Advertising-Lite.list,REJECT

# Privacy
RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/stable/rules/Privacy.list,REJECT

# Hijacking
RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/stable/rules/Hijacking.list,REJECT
```

Keep China_All, Google and all other existing sections in their original order. The stable branch must point to a reviewed release before using this template.
