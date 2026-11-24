# Direct exceptions

This list is a high-priority, explicit Direct override for reviewed service functionality. It is not a general domestic-domain list, nor a REJECT list. The initial four exact DOMAIN predicates are transferred verbatim from the existing profile, in the same order, with no expansion.

| Host | Scope |
| --- | --- |
| apd-pcdnwxlogin.teg.tencent-cloud.net | Existing WeChat PCDN login exception |
| apd-pcdnwxstat.teg.tencent-cloud.net | Existing WeChat PCDN status exception |
| dns.weixin.qq.com.cn | Existing WeChat DNS exception |
| smartpay-admin.fugetech.com | Existing payment exception |

The initial four already match Direct in the active spare profile. Advertising-Lite does not contain a covering domain predicate for them in the current pinned snapshot, but other reject lists or future updates may; retain priority rather than relying on absence from one list.

## Profile placement

Use a single fixed-commit URL for rules/Direct-Exceptions.list with the existing Direct policy, in precisely the former four inline rules' position: after private/home routing, before Advertising-Lite, Privacy-Curated and Hijacking-Curated. Do not move China_All or the whole WeChat list ahead of blocking rules. Do not remove overlapping predicates from WeChat.list; they do not replace the priority override. This does not alter AdGuard Home or DNS rules.

## Future maintenance

Require a specific hostname and evidence of a functionality regression or intended exception. Check existing matching rule, scope and impact; prefer exact DOMAIN only. Add a brief reason and non-sensitive evidence in this document, update the expected list in the regression test, submit a review-only PR, run CI, and manually adopt a fixed release commit after review. No wildcard, suffix, keyword, IP, URL regex or third-party list additions under this policy. Never publish private hostnames, credentials, requests with tokens, or full profiles.

## Acceptance and rollback

Check all four exact hosts before and after migration; require the new list to match Direct. Confirm representative advertising, privacy and hijack blocking, plus unrelated OpenAI and domestic routing. Check all external resources are ready with no index error. If a match fails, restore the four original inline predicates in the same position and verify. The spare iPhone is the only directly edited device; any device sharing the same iCloud profile may receive the edit automatically, including legacy Mac clients, so verify synchronized clients separately. Do not directly edit other devices. No automatic deployment by GitHub.
