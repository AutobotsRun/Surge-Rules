# Apple push subscription

The two existing inline suffix predicates are migrated verbatim to `rules/Apple-Push.list`. Keep their original order and the calling RULE-SET at the original position immediately before `Apple.list`. The profile supplies its existing HK policy; ordinary Apple traffic retains the existing Direct policy. No other rule, DNS configuration, or policy changes.

- `DOMAIN-SUFFIX,push.apple.com`
- `DOMAIN-SUFFIX,push-apple.com.akadns.net`

Pre-migration observation: api.push.apple.com matched the inline HK rule; push-apple.com.akadns.net matched the earlier China_All suffix akadns.net with Direct. This migration intentionally preserves existing effective precedence, not a routing correction. Any change to China_All or the position of the push set requires separate review and device testing.

Use the fixed candidate commit for initial verification, then manually publish to stable. Keep a backup of the two inline predicates for rollback. Rule matching is not proof of APNs delivery; verify actual push behavior on the spare device.
