#!/usr/bin/env python3
"""Read-only comparison of public domain blocklists; never publishes a RULE-SET."""
import collections
import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

SOURCES = {
    "current_advertising": "https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/01d9fb3132a75680441e01fa06b6a7d46fd69059/rules/Advertising.list",
    "current_privacy": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Privacy/Privacy_All.list",
    "current_hijacking": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Hijacking/Hijacking.list",
    "hagezi_light": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    "adguard_dns": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "stevenblack_base": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "blackmatrix7_advertising_lite": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/AdvertisingLite/AdvertisingLite_All.list",
    "oisd_small": "https://small.oisd.nl",
    "awavenue_surge_only_ads": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Surge-RULE-SET-Only.Ads.list",
    "denzel_mini": "https://raw.githubusercontent.com/DenzelVincent/adblock-dns-aggregator/output/adguard/mini.txt",
    # Peter Lowe original list, obtained through StevenBlack\'s independently updated
    # source mirror. License and attribution must be reviewed before distribution.
    "peter_lowe_hosts_mirror": "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/yoyo.org/hosts",
    # Official ads-only view (exclude entries tagged as trackers by the maintainer).
    "peter_lowe_ads_only": "https://pgl.yoyo.org/as/serverlist.php?hostformat=hosts&notrackers=1&showintro=0&mimetype=plaintext",
}
DOMAIN = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")
ADBLOCK = re.compile(r"\|\|([a-z0-9-]+(?:\.[a-z0-9-]+)+)\^")
KNOWN_GOOD = ["apd-pcdnwxlogin.teg.tencent-cloud.net",
              "apd-pcdnwxstat.teg.tencent-cloud.net",
              "dns.weixin.qq.com.cn", "smartpay-admin.fugetech.com"]


def fetch(name, url):
    p = urlsplit(url)
    if p.scheme != "https" or p.hostname not in {"raw.githubusercontent.com", "adguardteam.github.io", "small.oisd.nl", "oisd.nl", "pgl.yoyo.org"}:
        raise ValueError("unexpected source: " + name)
    with urlopen(Request(url, headers={"User-Agent": "lite-rule-audit/1.0"}), timeout=90) as response:
        r = urlsplit(response.geturl())
        if r.scheme != "https" or r.hostname not in {"raw.githubusercontent.com", "adguardteam.github.io", "small.oisd.nl", "oisd.nl", "pgl.yoyo.org"}:
            raise ValueError("unexpected redirect: " + name)
        data = response.read(36 * 1024 * 1024 + 1)
    if not 1000 <= len(data) <= 36 * 1024 * 1024 or data.lstrip().lower().startswith(b"<html"):
        raise ValueError("source empty, too large or invalid: " + name)
    return data


def covered(exact, suffix, hostname):
    if hostname in exact:
        return True
    labels = hostname.split(".")
    return any(".".join(labels[i:]) in suffix for i in range(len(labels)))


def surge_rules(data):
    exact, suffix, types = set(), set(), collections.Counter()
    for item in data.decode("utf-8-sig").splitlines():
        item = item.strip()
        if not item or item.startswith(("#", "//", ";")):
            continue
        kind, _, rest = item.partition(",")
        types[kind] += 1
        domain = rest.split(",", 1)[0].lower()
        if not DOMAIN.fullmatch(domain):
            continue
        if kind == "DOMAIN":
            exact.add(domain)
        elif kind == "DOMAIN-SUFFIX":
            suffix.add(domain)
    return exact, suffix, types


def candidate_rules(data, mode):
    domains, unsupported = set(), collections.Counter()
    for line in data.decode("utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", "[")):
            continue
        if mode == "adblock":
            m = ADBLOCK.fullmatch(line)
            if m:
                domains.add(m.group(1).lower())
            else:
                unsupported["unsupported_or_exception"] += 1
        else:
            fields = line.split()
            if len(fields) >= 2 and fields[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
                domains.update(x.lower() for x in fields[1:] if DOMAIN.fullmatch(x.lower()))
            else:
                unsupported["non_hosts_line"] += 1
    return domains, unsupported


def audit_native_ip_rules(data):
    """Counts structural IP risks; does not publish third-party IP entries."""
    summary = {"ipv4": 0, "ipv6": 0, "non_global": 0,
               "broad_ipv4_under_24": 0, "broad_ipv6_under_64": 0,
               "invalid": 0}
    for item in data.decode("utf-8-sig").splitlines():
        item = item.strip()
        kind, _, remainder = item.partition(",")
        if kind not in {"IP-CIDR", "IP-CIDR6"}:
            continue
        try:
            network = ipaddress.ip_network(remainder.split(",", 1)[0], strict=False)
            if (kind == "IP-CIDR") != (network.version == 4):
                raise ValueError("family mismatch")
        except ValueError:
            summary["invalid"] += 1
            continue
        if network.version == 4:
            summary["ipv4"] += 1
            if network.prefixlen < 24:
                summary["broad_ipv4_under_24"] += 1
        else:
            summary["ipv6"] += 1
            if network.prefixlen < 64:
                summary["broad_ipv6_under_64"] += 1
        if not network.is_global:
            summary["non_global"] += 1
    return summary


def analyze(name, data, mode, refs):
    if mode == "surge":
        exact, suffix, types = surge_rules(data)
        domains = exact | suffix
        skipped = collections.Counter({"non_domain_native_rules": sum(
            amount for kind, amount in types.items() if kind not in {"DOMAIN", "DOMAIN-SUFFIX"}
        )})
        keywords = {
            line.split(",", 1)[1].split(",", 1)[0].lower()
            for line in data.decode("utf-8-sig").splitlines()
            if line.startswith("DOMAIN-KEYWORD,")
        }
        snapshot_date = next((line[10:].strip() for line in
                              data.decode("utf-8-sig").splitlines()[:25]
                              if line.startswith("# UPDATED:")), None)
    else:
        domains, skipped = candidate_rules(data, mode)
        exact, suffix = (set(), domains) if mode == "adblock" else (domains, set())
        keywords, snapshot_date = set(), None
    if len(domains) < 100:
        raise ValueError("too few valid entries: " + name)
    if mode == "surge":
        minimum = 30000 if name == "blackmatrix7_advertising_lite" else 500
        if sum(types.values()) < minimum:
            raise ValueError("unexpectedly small native Surge snapshot: " + name)
    overlap = {
        source: sum(covered(exact, suffix, host) for host in domains)
        for source, (exact, suffix) in refs.items()
    }
    current_exact, current_suffix = refs["current_advertising"]
    # Reverse coverage is intentionally conservative: an exact candidate rule
    # cannot cover all subdomains of an existing DOMAIN-SUFFIX predicate.
    existing_exact_covered = sum(
        covered(exact, suffix, host) for host in current_exact
    )
    existing_suffix_covered = sum(
        covered(set(), suffix, host) for host in current_suffix
    )
    return {
        "name": name,
        "url": SOURCES[name],
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": mode,
        "source_updated_header": snapshot_date,
        "native_rule_type_counts": dict(types) if mode == "surge" else None,
        "native_ip_risk_summary": audit_native_ip_rules(data) if mode == "surge" else None,
        "unique_simple_domains": len(domains),
        "unsupported_or_exception_lines": sum(skipped.values()),
        "matched_by_existing_rule_sets": overlap,
        "not_matched_by_current_advertising": len(domains) - overlap["current_advertising"],
        "not_matched_by_any_existing_rule_set": sum(
            not any(covered(*refs[source], host) for source in refs) for host in domains
        ),
        "current_exact_domains_covered_by_candidate": existing_exact_covered,
        "current_suffix_domains_covered_by_candidate": existing_suffix_covered,
        "existing_exact_domains": len(current_exact),
        "existing_suffix_domains": len(current_suffix),
        "known_good_matched_by_candidate": {
            host: covered(exact, suffix, host) or any(token in host for token in keywords)
            for host in KNOWN_GOOD
        },
        "notes": "Native rules are not equivalent to DNS/Hosts rules. Native Surge IP/regex/AND and keyword rules are not fully evaluated by this simple domain comparison." if mode == "surge" else None,
    }



def study_small_pair(native_ads, hosts_ads_only):
    """Static, exact-domain merge estimate; never emits a downloadable list."""
    exact, suffix, types = surge_rules(native_ads)
    hosts, unsupported = candidate_rules(hosts_ads_only, "hosts")
    if unsupported or len(hosts) < 1000:
        raise ValueError("unexpected ads-only hosts format")
    extra_hosts = {host for host in hosts if not covered(exact, suffix, host)}
    merged_exact = exact | extra_hosts
    keywords = {
        line.split(",", 1)[1].split(",", 1)[0].lower()
        for line in native_ads.decode("utf-8-sig").splitlines()
        if line.startswith("DOMAIN-KEYWORD,")
    }
    return {
        "method": "static native RULE-SET + conservative exact-hosts deduplication",
        "native_rules_total": sum(types.values()),
        "hosts_ads_only_unique": len(hosts),
        "hosts_already_covered_by_native_exact_or_suffix": len(hosts) - len(extra_hosts),
        "hosts_added_as_exact_domain_rules": len(extra_hosts),
        "estimated_merged_native_rule_count": sum(types.values()) + len(extra_hosts),
        "known_good_matched_by_domain_or_keyword": {
            host: covered(merged_exact, suffix, host) or
                  any(token in host for token in keywords)
            for host in KNOWN_GOOD
        },
        "limits": "Not a published list or measured effectiveness. IP-CIDR is not resolved against known-good domains; keyword, CNAME, updates, and live traffic need further checking."
    }


def main():
    blobs = {name: fetch(name, url) for name, url in SOURCES.items()}
    ref_results = {name: surge_rules(blobs[name]) for name in
                   ("current_advertising", "current_privacy", "current_hijacking")}
    if sum(ref_results["current_advertising"][2].values()) < 250000:
        raise ValueError("current advertising list unexpectedly short")
    refs = {name: (result[0], result[1]) for name, result in ref_results.items()}
    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": "read-only, predicate-based comparison (not an effective blocking benchmark)",
        "sources": {name: {"size": len(blobs[name]), "sha256": hashlib.sha256(blobs[name]).hexdigest(),
                           "types": dict(value[2])} for name, value in ref_results.items()},
        "candidates": [
            analyze(name, blobs[name], mode, refs) for name, mode in
            (("hagezi_light", "adblock"), ("adguard_dns", "adblock"),
             ("stevenblack_base", "hosts"),
             ("blackmatrix7_advertising_lite", "surge"), ("oisd_small", "adblock"),
             ("awavenue_surge_only_ads", "surge"), ("denzel_mini", "adblock"),
             ("peter_lowe_hosts_mirror", "hosts"),
             ("peter_lowe_ads_only", "hosts"))
        ],
        "proposed_awa_plus_peter_ads_only": study_small_pair(blobs["awavenue_surge_only_ads"], blobs["peter_lowe_ads_only"]),
        "limits": "Simple exact domains and suffixes only. For native Surge false-positive checks also test DOMAIN-KEYWORD; IP/regex/AND not simulated. Ignores modifiers, exceptions, precedence, DNS/CNAME, traffic distribution. No third-party content is redistributed.",
    }
    path = Path("/tmp/advertising-lite-comparison.json")
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write("## Lite candidate comparison (read-only)\n\n")
            output.write("| Source | Simple domains | Covered by existing Ad | New exact hostnames | Unsupported lines |\n")
            output.write("|---|---:|---:|---:|---:|\n")
            for c in report["candidates"]:
                output.write("| {} | {:,} | {:,} | {:,} | {:,} |\n".format(
                    c["name"], c["unique_simple_domains"],
                    c["matched_by_existing_rule_sets"]["current_advertising"],
                    c["not_matched_by_current_advertising"],
                    c["unsupported_or_exception_lines"]))
            output.write("\nNo list or device has been changed.\n")


if __name__ == "__main__":
    main()
