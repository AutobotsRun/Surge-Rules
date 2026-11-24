# Garmin focused rules candidate (2026-11-24)

Scope: replace the existing standalone connect.garmin.com suffix US rule with a focused six-predicate ruleset on the designated spare device only. Preserve its position before China_All and below existing block rules. No changes to QUIC, DNS, China_All, shared services or other device profiles.

## Observed evidence

During a user-run sequence opening Garmin Connect, 佳速度 and Connect IQ on Wi-Fi, the recent/active request snapshots contained connect.garmin.com (US), connectapi.garmin.com (Direct, HTTPS and QUIC), diauth.garmin.com, account.customer.services.garmin.com, mobile-auth.security.services.garmin.com, services.garmin.com, api.gcs.garmin.com, static.garmin.com, sports.garmin.com and apps.garmin.com (Direct). apps.garmin.com was captured in the final snapshot with bidirectional bytes. A preceding deduplicated snapshot included 8,041,323 bytes received from services.garmin.com and 9,594,905 from sports.garmin.com; preserve those routes. Ten of fifteen connectapi connections in that snapshot had zero received bytes, including QUIC; this is not proof of routing failure or of a need to disable QUIC. Recent requests are limited and the live event tool failed; snapshots do not prove complete app coverage or identify which app used every shared hostname.

## Candidate decisions

- Preserve the existing suffix for connect.garmin.com.
- Add exact connectapi.garmin.com, diauth.garmin.com, account.customer.services.garmin.com, mobile-auth.security.services.garmin.com and apps.garmin.com. These are observed destinations, not a copy of an external ruleset.
- Do not match all garmin.com, all services.garmin.com, sports.garmin.com, api.gcs.garmin.com, static.garmin.com or download.garmin.com. Do not add unobserved sso or ghs hostnames by default.
- Authentication endpoints may be shared by the international and China apps. US routing is a trial, not an established requirement; validate both app families. If shared authentication breaks, restore those hosts to previous routing or roll back the whole candidate. No assumption about specific endpoints' application roles beyond observed destinations and hostname context.

## Acceptance

Review CI, then replace the single existing Garmin line with a fixed-SHA RULE-SET in the same position on the spare device. Confirm all six candidate destinations hit US, domestic and common-service hosts retain the existing route, and existing ad/privacy/WeChat/payment priorities remain unchanged. Retest Connect data refresh, 佳速度 data/content and Connect IQ store; check account access without forcing sign-out. Compare HTTPS/QUIC results and network interfaces; roll back if regression. The repository contains only destination names, no request bodies, account data, device identifiers or full profiles. No device changes in this PR.
