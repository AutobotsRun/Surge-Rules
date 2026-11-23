#!/usr/bin/env python3
"""Read-only, source-pinned predicate audit of four public Surge rule sets.

No private profile data, no deployment, no GitHub repo rule mirroring.
Rule entailment is NOT an empirical request-blocking overlap benchmark.
"""
import hashlib
import json
import sys
from urllib.request import Request, urlopen

SOURCE_PINS = {
    "lite": (
        "https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/"
        "41cc017763ae9ef2127eac28be1effd11ef1080e/"
        "experiments/advertising-lite/Advertising-Lite-TEST.list",
        "ea6d2316d16180147930a363f928976a598d9431",
    ),
    "privacy": (
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
        "master/rule/Surge/Privacy/Privacy_All.list",
        "a75df944a7a0fcae26f762059c0f7fd72f42c420",
    ),
    "hijacking": (
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
        "master/rule/Surge/Hijacking/Hijacking.list",
        "0ffb798f0ce5f098fd3e7dc889fbbca94b9bdd5d",
    ),
    "china": (
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
        "master/rule/Surge/China/China_All.list",
        "bba28360d9dc0310b418df6d9fb7dfa76588c895",
    ),
}
EXPECTED_COUNT = {"lite": 2890, "privacy": 39936, "hijacking": 228, "china": 3752}
KNOWN_GOOD = (
    "apd-pcdnwxlogin.teg.tencent-cloud.net",
    "apd-pcdnwxstat.teg.tencent-cloud.net",
    "dns.weixin.qq.com.cn",
    "smartpay-admin.fugetech.com",
)
ALLOWED_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR",
    "IP-CIDR6", "USER-AGENT",
}


def git_blob_sha(content):
    return hashlib.sha1(
        ("blob %d\0" % len(content)).encode("ascii") + content
    ).hexdigest()


def fetch_checked(url, expected_blob):
    req = Request(url, headers={"User-Agent": "surge-rules-readonly-audit/1"})
    with urlopen(req, timeout=35) as resp:
        content = resp.read()
    if git_blob_sha(content) != expected_blob:
        raise ValueError("public source changed; new review required")
    return content


def parse(data):
    """Return (rule_type, lowercase_value); do not change source semantics."""
    result = []
    for lineno, raw in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        bits = line.split(",")
        if len(bits) not in (2, 3):
            raise ValueError("unexpected rule fields at line %d" % lineno)
        kind, value = bits[0].strip(), bits[1].strip().lower()
        if kind not in ALLOWED_TYPES or not value:
            raise ValueError("unexpected rule type/value at line %d" % lineno)
        if len(bits) == 3 and bits[2] != "no-resolve":
            raise ValueError("unexpected rule flag at line %d" % lineno)
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"} and len(bits) != 2:
            raise ValueError("domain flag not supported in this comparison")
        result.append((kind, value))
    return result


class DomainIndex:
    """Conservative, complete predicate entailment (not intersection)."""
    def __init__(self, rules):
        self.exact = {v for kind, v in rules if kind == "DOMAIN"}
        self.suffix = {v for kind, v in rules if kind == "DOMAIN-SUFFIX"}
        self.keywords = {v for kind, v in rules if kind == "DOMAIN-KEYWORD"}

    def matching_suffix(self, value):
        while value:
            if value in self.suffix:
                return value
            _, separator, value = value.partition(".")
            if not separator:
                return None
        return None

    def covers(self, rule):
        kind, val = rule
        if kind == "DOMAIN":
            if val in self.exact:
                return "exact"
            if self.matching_suffix(val) is not None:
                return "suffix"
            if any(k in val for k in self.keywords):
                return "keyword"
        elif kind == "DOMAIN-SUFFIX":
            if self.matching_suffix(val) is not None:
                return "suffix"
            # A keyword contained in the base suffix matches every subdomain.
            if any(k in val for k in self.keywords):
                return "keyword"
        elif kind == "DOMAIN-KEYWORD":
            # Any host matching the more specific keyword also matches its
            # substring. Other rule types cannot fully cover a keyword rule.
            if any(k in val for k in self.keywords):
                return "keyword"
        # IP and USER-AGENT entailment intentionally not computed.
        return None

    def host_matches(self, host):
        return (
            host in self.exact
            or self.matching_suffix(host) is not None
            or any(keyword in host for keyword in self.keywords)
        )


def coverage(subject, reference):
    idx = DomainIndex(reference)
    reasons = {"exact": 0, "suffix": 0, "keyword": 0}
    found = []
    for rule in subject:
        why = idx.covers(rule)
        if why is not None:
            reasons[why] += 1
            found.append(rule)
    return {"covered_count": len(found), "reasons": reasons, "found": found}


def audit(sets):
    for name, expected in EXPECTED_COUNT.items():
        if len(sets[name]) != expected:
            raise ValueError("unexpected rule count for " + name)
    lite, privacy, hijacking, china = (
        sets[n] for n in ("lite", "privacy", "hijacking", "china")
    )
    named = {
        "lite_fully_covered_by_privacy": coverage(lite, privacy),
        "privacy_fully_covered_by_lite": coverage(privacy, lite),
        "lite_fully_covered_by_hijacking": coverage(lite, hijacking),
        "hijacking_fully_covered_by_lite_or_privacy":
            coverage(hijacking, lite + privacy),
        "china_fully_covered_by_privacy": coverage(china, privacy),
    }
    exact = set(lite) & set(privacy)
    privacy_index = DomainIndex(privacy)
    hijack_index = DomainIndex(hijacking)
    lite_index = DomainIndex(lite)

    return {
        "type": "static predicate entailment, NOT real traffic overlap",
        "source_rule_counts": {name: len(rules) for name, rules in sets.items()},
        "metrics": {
            name: {"count": v["covered_count"], "by_rule_type_match": v["reasons"]}
            for name, v in named.items()
        },
        "exact_same_type_same_value_lite_privacy": len(exact),
        "known_good_conflicts": {
            host: [
                name for name, index in (
                    ("privacy", privacy_index), ("hijacking", hijack_index),
                    ("lite", lite_index)
                ) if index.host_matches(host)
            ] for host in KNOWN_GOOD
        },
        "privacy_review_candidates": {
            host: privacy_index.host_matches(host)
            for host in (
                "safebrowsing.googleapis.com",
                "safebrowsing.urlsec.qq.com",
                "analytics.strava.com",
            )
        },
        "note": (
            "Only DOMAIN/DOMAIN-SUFFIX/DOMAIN-KEYWORD rules were compared. "
            "IP/USER-AGENT conditions and empirical request-level overlap "
            "are excluded; later rule order and DNS sinkholes also matter."
        ),
    }


def main():
    blobs = {name: fetch_checked(*spec) for name, spec in SOURCE_PINS.items()}
    sets = {name: parse(data) for name, data in blobs.items()}
    result = audit(sets)
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
