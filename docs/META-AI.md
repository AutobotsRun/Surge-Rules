# Meta AI focused candidate

Scope: standalone Meta AI web and app, existing US routing policy. Not a drop-in equivalent to the old 21-line RuleGo fork. Do not include all of Meta, Facebook, Instagram, WhatsApp, Llama or Muse by default.

- MIT upstream: https://github.com/v2fly/domain-list-community/blob/dfa5b1c2258289bdbee70d06352cca23b9bdac7f/data/meta ; exact original snapshot and MIT license retained under sources/v2fly/. Extract only meta.ai, metaaiusercontent.com and metaaivm.com. Convert bare domains to Surge DOMAIN-SUFFIX, preserving subdomain semantics.
- Official entry: https://ai.meta.com/meta-ai/ and https://www.meta.com/help/artificial-intelligence/943942350800511/ ; ai.meta.com is exact match.
- Provisional exact login dependency auth.meta.com: public implementation https://github.com/TED-H-com/multi-ai-chat-desktop (Meta AI SSO host) and https://www.meta.com/account/ (shared Meta account). Shared login may affect other Meta apps, so do not match meta.com as a suffix. No live app traffic yet confirms necessity.
- No copied rules from logicrw/RuleGo. The existing monitor-only entry remains unchanged for rollback; upstream MIT source is a reviewed pinned snapshot, not in current automated .list monitor.

Acceptance: keep old subscription active until the owner opens Meta AI on the spare and exercises chat, login if needed, and media/voice if used. Record only relevant destination hostnames and matched policies, not prompts, URLs with private parameters, or credentials. Compare observed dependencies with this candidate, expand precisely only on evidence, validate CI, merge, then switch the single URL at a fixed SHA and retest. Roll back if any function fails. No device changes in this PR.
