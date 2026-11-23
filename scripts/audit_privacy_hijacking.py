#!/usr/bin/env python3
"""Read-only, snapshot-pinned comparison of Surge rulesets.

Downloads only audited public Git blobs, checks Git-object SHA1 and expected
rule-type counts, outputs aggregate JSON. It neither redistributes source
lists nor reads/writes device configurations.
"""
import base64
import hashlib
import ipaddress
import json
import os
import urllib.request

SOURCES = {
    "privacy": ("blackmatrix7/ios_rule_script",
                "a75df944a7a0fcae26f762059c0f7fd72f42c420",
                {"DOMAIN": 19, "DOMAIN-SUFFIX": 39897,
                 "DOMAIN-KEYWORD": 9, "IP-CIDR": 11}),
    "lite": ("AutobotsRun/Surge-Rules",
             "ea6d2316d16180147930a363f928976a598d9431",
             {"DOMAIN": 2875, "DOMAIN-SUFFIX": 11, "DOMAIN-KEYWORD": 4}),
    "hijacking": ("blackmatrix7/ios_rule_script",
                  "0ffb798f0ce5f098fd3e7dc889fbbca94b9bdd5d",
                  {"DOMAIN": 1, "DOMAIN-SUFFIX": 185, "IP-CIDR": 42}),
    "china": ("blackmatrix7/ios_rule_script",
              "bba28360d9dc0310b418df6d9fb7dfa76588c895",
              {"DOMAIN": 17, "DOMAIN-SUFFIX": 3674,
               "DOMAIN-KEYWORD": 9, "IP-CIDR": 17,
               "IP-CIDR6": 4, "USER-AGENT": 31}),
}
TYPES = ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
         "IP-CIDR", "IP-CIDR6", "USER-AGENT")

# Named functionality endpoints for **review**, not automatic allowlisting.
# Google documents its standard Safe Browsing API and OHTTP gateway hosts;
# the Tencent hostname remains a candidate until owner/function is confirmed.
SECURITY_REVIEW_HOSTS = (
    "safebrowsing.googleapis.com",
    "safebrowsingohttpgateway.googleapis.com",
    "safebrowsing.urlsec.qq.com",
)
PROTECTED = (
    "apd-pcdnwxlogin.teg.tencent-cloud.net",
    "apd-pcdnwxstat.teg.tencent-cloud.net",
    "dns.weixin.qq.com.cn",
    "smartpay-admin.fugetech.com",
    "wxa.wxs.qq.com",
    "wximg.wxs.qq.com",
    "wxsmw.wxs.qq.com",
    "wxaintpcos.wxqcloud.qq.com.cn",
    "hybrid.miniapp.taobao.com",
    "mini-prog-drm.vodplayvideo.net",
    "pay.sboot.cn",
    "sdkconfig.video.qq.com",
)


def parse_rules(data):
    rules = {kind: set() for kind in TYPES}
    for lineno, raw in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "!", ";", "//")):
            continue
        parts = line.split(",")
        kind = parts[0].strip()
        if kind not in rules or len(parts) < 2 or not parts[1].strip():
            raise ValueError("unrecognized rule at line " + str(lineno))
        value = parts[1].strip().lower()
        if kind in ("IP-CIDR", "IP-CIDR6"):
            if len(parts) > 3 or (len(parts) == 3 and parts[2] != "no-resolve"):
                raise ValueError("unsupported IP rule flags")
            net = ipaddress.ip_network(value, strict=True)
            if (kind == "IP-CIDR") != (net.version == 4):
                raise ValueError("IP version mismatch")
        elif len(parts) != 2:
            raise ValueError("unsupported non-IP rule flags")
        if value in rules[kind]:
            raise ValueError("duplicate entry " + kind + "," + value)
        rules[kind].add(value)
    return rules


def parents(host):
    labels = host.lower().split(".")
    return (".".join(labels[i:]) for i in range(len(labels)))


def host_match(host, target):
    host = host.lower()
    if host in target["DOMAIN"]:
        return "DOMAIN"
    if any(s in target["DOMAIN-SUFFIX"] for s in parents(host)):
        return "DOMAIN-SUFFIX"
    if any(k in host for k in target["DOMAIN-KEYWORD"]):
        return "DOMAIN-KEYWORD"
    return None


def covered(kind, value, target):
    """Whether every destination matching source rule matches a target rule.

    This is universal coverage, NOT the count of overlapping live DNS flows.
    """
    if kind == "DOMAIN":
        return host_match(value, target)
    if kind == "DOMAIN-SUFFIX":
        if any(s in target["DOMAIN-SUFFIX"] for s in parents(value)):
            return "DOMAIN-SUFFIX"
        if any(k in value for k in target["DOMAIN-KEYWORD"]):
            return "DOMAIN-KEYWORD"
    if kind == "DOMAIN-KEYWORD":
        if any(k in value for k in target["DOMAIN-KEYWORD"]):
            return "DOMAIN-KEYWORD"
    if kind in ("IP-CIDR", "IP-CIDR6"):
        a = ipaddress.ip_network(value)
        if any(a.subnet_of(ipaddress.ip_network(s))
               for s in target[kind]):
            return kind
    return None


def compare(source, target):
    by_kind = {}
    for kind, values in source.items():
        identical = len(values & target[kind])
        mechanisms = {}
        for value in values:
            reason = covered(kind, value, target)
            if reason:
                mechanisms[reason] = mechanisms.get(reason, 0) + 1
        by_kind[kind] = {
            "total": len(values),
            "identical": identical,
            "covered": sum(mechanisms.values()),
            "covering_types": dict(sorted(mechanisms.items())),
        }
    return {
        "total_source_rules": sum(len(v) for v in source.values()),
        "total_rules_fully_covered": sum(v["covered"] for v in by_kind.values()),
        "breakdown": by_kind,
    }



def china_redundancy(book):
    """Count China predicates wholly covered by OTHER predicates in same list.

    Equivalent routing decision depends on keeping the covering rule and its
    policy in the same RULE-SET. USER-AGENT and cross-type IP/domain matching
    are deliberately excluded. Counts do not measure latency or traffic.
    """
    suffixes = book["DOMAIN-SUFFIX"]
    keywords = book["DOMAIN-KEYWORD"]
    by_kind = {}
    samples = {}
    for kind in ("DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"):
        redundant = []
        for val in sorted(book[kind]):
            if kind in ("DOMAIN", "DOMAIN-SUFFIX"):
                # DOMAIN may be covered by same-name suffix, but a suffix
                # cannot be considered to cover itself.
                candidates = list(parents(val))
                if kind == "DOMAIN-SUFFIX":
                    candidates = candidates[1:]
                match = any(x in suffixes for x in candidates) or any(
                    key in val for key in keywords)
            else:
                net = ipaddress.ip_network(val)
                match = any(
                    net.subnet_of(ipaddress.ip_network(other))
                    for other in book[kind] if other != val)
            if match:
                redundant.append(val)
        by_kind[kind] = len(redundant)
        samples[kind] = redundant[:8]
    return {
        "total_fully_covered": sum(by_kind.values()),
        "by_rule_type": by_kind,
        "examples": samples,
        "note": (
            "Only individually provable predicate redundancy, holding source "
            "and destination policy fixed. Does not justify removing broad "
            "keyword rules, which may be policy overreach rather than redundancy."
        ),
    }


def audit(rules):
    p, l, h, c = [rules[k] for k in ("privacy", "lite", "hijacking", "china")]
    def addresses(rulebook):
        return [ipaddress.ip_network(value) for kind in ("IP-CIDR", "IP-CIDR6")
                for value in rulebook[kind]]
    hip, pip = addresses(h), addresses(p)
    protected_hits = {
        name: {key: host_match(name, rules[key]) for key in
               ("lite", "privacy", "hijacking")}
        for name in PROTECTED
    }
    overlaps = sum(any(a.overlaps(b) for b in pip) for a in hip)
    wide = sorted(str(a) for a in hip if a.prefixlen < a.max_prefixlen)
    return {
        "source_git_blob_shas": {k: SOURCES[k][1] for k in SOURCES},
        "rule_counts": {k: {kind: len(v) for kind, v in r.items() if v}
                        for k, r in rules.items()},
        "lite_fully_covered_by_privacy": compare(l, p),
        "privacy_fully_covered_by_lite": compare(p, l),
        "hijacking_fully_covered_by_privacy": compare(h, p),
        "hijacking_fully_covered_by_lite": compare(h, l),
        "hijacking_suffixes_fully_covered_by_china": sum(
            covered("DOMAIN-SUFFIX", value, c) is not None
            for value in h["DOMAIN-SUFFIX"]
        ),
        "hijacking_ip_ranges_intersecting_privacy_ip_ranges": overlaps,
        "hijacking_wide_ip_ranges": wide,
        "china_internal_redundancy": china_redundancy(c),
        "protected_host_hits": protected_hits,
        "security_endpoint_review": {
            host: {key: bool(host_match(host, rules[key]))
                   for key in ("lite", "privacy", "hijacking")}
            for host in SECURITY_REVIEW_HOSTS
        },
        "security_endpoint_caveat": (
            "Static match only; no proof that Chrome, Safari or another "
            "installed app actually calls the endpoint, and no assessment of "
            "AdGuard Home DNS or protected browsing functionality."
        ),
        "limitation": (
            "These are universal static rule-coverage comparisons. They do not "
            "measure actual blocked traffic, AdGuard Home DNS behavior, "
            "real-world false positives, stale IP ownership or speed."
        ),
    }


def fetch_pinned_blob(repo, sha):
    url = "https://api.github.com/repos/" + repo + "/git/blobs/" + sha
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "surge-rules-research-read-only"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                timeout=40) as response:
        record = json.load(response)
    if record.get("encoding") != "base64":
        raise ValueError("unexpected Git blob encoding")
    body = base64.b64decode(record["content"], validate=False)
    digest = hashlib.sha1(
        b"blob " + str(len(body)).encode("ascii") + b"\0" + body
    ).hexdigest()
    if digest != sha or record.get("sha") != sha:
        raise ValueError("Git blob hash mismatch")
    return body


def main():
    books = {}
    for name, (repo, sha, expected) in SOURCES.items():
        raw = fetch_pinned_blob(repo, sha)
        rules = parse_rules(raw)
        actual = {k: len(v) for k, v in rules.items() if v}
        if actual != expected:
            raise ValueError(name + ": upstream count has changed")
        books[name] = rules
    print(json.dumps(audit(books), indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
