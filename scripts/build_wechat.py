#!/usr/bin/env python3
"""Deterministic, offline Surge rule-set builder. No network access or device writes."""
from pathlib import Path
import hashlib
import ipaddress
import sys

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "sources/blackmatrix7/WeChat.list"
PCDN = ROOT / "custom/WeChat-PCDN.list"
CDN = ROOT / "custom/WeChat-CDN.list"
OUTPUT = ROOT / "rules/WeChat.list"


def parse(path):
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith(("RULE-SET,", "DOMAIN-SET,")):
            raise ValueError("Nested rule sets are not supported: " + str(path))
        if s.count(",") > 3:
            raise ValueError("Unexpected rule form: " + s)
        lines.append(s)
    if not lines:
        raise ValueError("Empty source: " + str(path))
    return lines


def main():
    # Overrides first for diff visibility; policy selection stays in Surge profile.
    user = parse(CDN) + parse(PCDN)
    vendor = parse(UPSTREAM)
    merged, seen = [], set()
    for rule in user + vendor:
        # Keep every distinct upstream predicate; deduplicate only exact rules.
        if rule not in seen:
            seen.add(rule)
            merged.append(rule)
    if "DOMAIN,apd-pcdnwxlogin.teg.tencent-cloud.net" not in seen:
        raise ValueError("PCDN exception missing")
    for line in parse(CDN):
        cols = line.split(",")
        if len(cols) != 3 or cols[0] != "IP-CIDR" or cols[2] != "no-resolve":
            raise ValueError("Unexpected CDN exception: " + line)
        if ipaddress.ip_network(cols[1], strict=True).prefixlen != 32:
            raise ValueError("CDN exception must be /32")
    header = [
        "# GENERATED FILE - do not edit directly",
        "# blackmatrix7/ios_rule_script WeChat source (GPL-2.0):",
        "# https://github.com/blackmatrix7/ios_rule_script",
        "# Source snapshot: sources/blackmatrix7/WeChat.list",
        "# License copy: sources/blackmatrix7/LICENSE",
        "# Local additions: custom/WeChat-CDN.list and custom/WeChat-PCDN.list",
        "# This file contains only predicates. The calling RULE-SET supplies policy.",
        "# IMPORTANT: load this WeChat rule set BEFORE Advertising_All.list.",
        "# Review upstream updates and licensing; do not silently replace this file.",
        "",
    ]
    result = "\n".join(header + merged) + "\n"
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if "--check" in sys.argv:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != result:
            raise SystemExit("rules/WeChat.list out of sync; regenerate and review the diff")
        print(f"OK: {len(merged)} rules, upstream={len(vendor)}, custom={len(user)}")
    else:
        OUTPUT.write_text(result, encoding="utf-8")
        print(f"Built {OUTPUT.relative_to(ROOT)}: {len(merged)} rules")
    print("sha256=" + hashlib.sha256(result.encode("utf-8")).hexdigest())


if __name__ == "__main__":
    main()
