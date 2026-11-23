# AdGuard Home: reviewed DNS allowlist

This directory contains a small, **manually reviewed** allowlist of DNS filtering false positives. It is intended for the user's AdGuard Home; no credentials, private IPs, or account identifiers are published.

## Subscribe

In AdGuard Home, open **Filters → DNS allowlists → Add allowlist → Add a custom list**, name it `AutobotsRun - Verified Allowlist`, and use:

```text
https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/main/adguard/allowlist.txt
```

The `main` URL intentionally follows reviewed future merges; it is **not** pinned to a commit. Keep periodic updates enabled, or manually click Update after an approved change. Inspect the query log to confirm the correct exception list is used. Keep existing local exceptions until the remote list has successfully loaded and DNS lookups work, then remove duplicates if desired.

## Change control and scope

- One exact reviewed DNS hostname per line, in AdGuard syntax `@@||host.example^`; comments record the reason and observations.
- `@@||host.example^` can also match subdomains of that host, **not** arbitrary siblings under its parent. No parent-domain wildcard allowlisting.
- Do not add payment, identity, or tracking infrastructure domains without observing a real false positive and testing a narrow exception.
- The allowlist only changes **AdGuard Home DNS filtering**. Surge has independent blocking and routing; it must be diagnosed/adjusted separately. An AdGuard Home allowlist is not a Surge DIRECT rule.
- Test first, then review via a PR; GitHub Actions validates the format but **does not deploy** or edit the AdGuard Home server.
- To roll back, disable this subscription in AdGuard Home or revert the relevant GitHub commit, then update the filter.

## Initial verified entries (2026-11-23)

- `apd-pcdnwxlogin.teg.tencent-cloud.net`: WeChat PCDN login
- `apd-pcdnwxstat.teg.tencent-cloud.net`: WeChat PCDN status
- `dns.weixin.qq.com.cn`: WeChat DNS blocked by anti-AD
- `smartpay-admin.fugetech.com`: SmartPay mini program, blocked during sign-in and account-page requests
