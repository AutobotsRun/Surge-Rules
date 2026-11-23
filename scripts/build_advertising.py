#!/usr/bin/env python3
"""Fail-closed advertising rule snapshot transformer. Never writes Surge profiles.

Input: downloaded upstream Advertising_All.list as a local file.
Output: reviewed candidate rules/Advertising.list, with exact exclusions.
No regex substitution and no broad allowlist. On failure, no output overwritten.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/advertising-exclusions.json"
OUTPUT = ROOT / "rules/Advertising.list"
MAX_BYTES = 64 * 1024 * 1024
MAX_LINES = 1_500_000
MIN_RULES = 1000


def load_exclusions(config):
    cfg = json.loads(config.read_text(encoding="utf-8"))
    if cfg.get("schema") != 1 or not isinstance(cfg.get("exclusions"), list):
        raise ValueError("Invalid exclusion catalog")
    approved = set()
    for x in cfg["exclusions"]:
        domain = x["value"].lower()
        if x.get("type") != "DOMAIN" or not x.get("approved_for_test"):
            raise ValueError("Only approved exact DOMAIN exclusions are supported")
        if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", domain):
            raise ValueError("Invalid domain exclusion: " + domain)
        approved.add("DOMAIN," + domain)
    if not approved or len(approved) != len(cfg["exclusions"]):
        raise ValueError("Empty or duplicated exclusions")
    source = urllib.parse.urlsplit(cfg["source"])
    if source.scheme != "https" or source.hostname != "raw.githubusercontent.com":
        raise ValueError("Unexpected source host")
    return cfg, approved


def covering_rule(rule, hostname):
    fields = rule.split(",")
    kind = fields[0].upper()
    value = fields[1].lower().strip() if len(fields) > 1 else ""
    if kind == "DOMAIN" and value == hostname:
        return True
    if kind == "DOMAIN-SUFFIX" and (hostname == value or hostname.endswith("." + value)):
        return True
    if kind == "DOMAIN-KEYWORD" and value and value in hostname:
        return True
    if kind == "DOMAIN-WILDCARD":
        # Conservative: any wildcard is escalated for human review, not blindly removed.
        return True
    if kind in ("URL-REGEX", "AND", "OR", "NOT", "RULE-SET", "DOMAIN-SET"):
        # Can't safely prove non-overlap without real rule evaluation.
        return True
    if kind in ("IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"):
        # Address-only rules cannot be safely excluded for a hostname at compile time.
        # Report separately, but they do not trigger mass deletion.
        return False
    return False


def transform(raw, exclusions, strict=True):
    if len(raw) > MAX_BYTES:
        raise ValueError("Upstream exceeds 64 MiB limit")
    data = raw.decode("utf-8-sig")
    if "\0" in data or data.lstrip().lower().startswith(("<html", "<!doctype")):
        raise ValueError("Unexpected HTML or binary content")
    lines = data.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError("Too many rules")
    active = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith(("#", "//", ";"))]
    if strict and len(active) < MIN_RULES:
        raise ValueError("Unexpectedly small upstream advertising rule set")
    targets = {line.split(",", 1)[1] for line in exclusions}
    removed = []
    cleaned = []
    for original in lines:
        text = original.strip()
        normalized = text.lower()
        if normalized in {x.lower() for x in exclusions}:
            removed.append(text)
        else:
            cleaned.append(original)
    if sorted(x.lower() for x in removed) != sorted(x.lower() for x in exclusions):
        raise ValueError("Expected EXACT exclusion missing or duplicated. STOP; inspect upstream changes.")
    risks = []
    for line in cleaned:
        s = line.strip()
        if not s or s.startswith(("#", "//", ";")):
            continue
        for domain in targets:
            if covering_rule(s, domain):
                risks.append(s)
                if len(risks) >= 15:
                    break
        if len(risks) >= 15:
            break
    if risks:
        raise ValueError("Potential remaining rules can cover excluded domain(s): " + repr(risks))
    heading = [
        "# Generated from blackmatrix7 ios_rule_script (GPL-2.0)",
        "# Upstream: https://github.com/blackmatrix7/ios_rule_script",
        "# License: sources/blackmatrix7/LICENSE",
        "# Review config/advertising-exclusions.json and upstream diff before release.",
        "# Do not modify this generated file directly.",
        "",
    ]
    result = "\n".join(heading + cleaned).rstrip() + "\n"
    return result, removed, len(active)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, default=OUTPUT)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()
    cfg, excluded = load_exclusions(CONFIG)
    raw = args.input.read_bytes()
    result, removed, count = transform(raw, excluded)
    info = {
        "upstream_url": cfg["source"],
        "upstream_sha256": hashlib.sha256(raw).hexdigest(),
        "generated_sha256": hashlib.sha256(result.encode()).hexdigest(),
        "original_active_rules": count,
        "removed_exact_rules": removed,
        "remaining_active_rules": count - len(removed),
    }
    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != result:
            raise SystemExit("Generated advertising rules differ from approved snapshot")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8")
    if args.report:
        args.report.write_text(json.dumps(info, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(info, ensure_ascii=False))


if __name__ == "__main__":
    main()
