#!/usr/bin/env python3
"""Fail-closed, non-deploying Lite preview: emits metadata ONLY, never list files.

All rules remain in memory; nothing is written to rules/, a public artifact,
or a device. Pinned public-source SHA-256 values require human review to update.
"""
import hashlib
import ipaddress
import json
import re

from research_advertising_lite import (
    DOMAIN, KNOWN_GOOD, REVIEW_NATIVE_HOSTS, SOURCES, covered, fetch,
)

# Snapshot digests verified in GitHub Actions on 2026-11-23.
PINS = {
    "awavenue_surge_only_ads": "45cb8e7fc318765c85353c5ddfcabd216978288ba271de7f32e085a876319832",
    "peter_lowe_ads_only": "f1e3eaf111ed2840a4630b9a94f98169988eea5fde282fee62b610410879d1e5",
}
# These *public upstream* hostnames are review candidates, not established
# false positives. Exclude them from preview, not from active production.
REVIEW_EXCLUSIONS = set(REVIEW_NATIVE_HOSTS)
KEYWORD = re.compile(r"[a-z0-9.-]{8,}")
ALLOWED_NATIVE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6"}


def parse_native(data):
    """Strict reader: preserve native semantics, omit IP, quarantine candidates."""
    native_rules = set()
    omitted_ip = 0
    omitted_review = set()
    for number, raw in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        parts = line.split(",")
        kind = parts[0]
        if kind not in ALLOWED_NATIVE_TYPES:
            raise ValueError("unsupported native rule type at line " + str(number))
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            if len(parts) != 3 or parts[2] != "no-resolve":
                raise ValueError("unsupported native IP syntax")
            try:
                ip = ipaddress.ip_network(parts[1], strict=False)
            except ValueError as exc:
                raise ValueError("invalid native IP CIDR") from exc
            if (kind == "IP-CIDR") != (ip.version == 4):
                raise ValueError("native IP family mismatch")
            omitted_ip += 1
            continue
        if len(parts) != 2:
            raise ValueError("native domain rule has unexpected arguments")
        value = parts[1].strip().lower()
        if kind == "DOMAIN-KEYWORD":
            if not KEYWORD.fullmatch(value) or not value.startswith("-"):
                raise ValueError("keyword too broad or invalid")
        elif not DOMAIN.fullmatch(value):
            raise ValueError("invalid native domain")
        if kind == "DOMAIN" and value in REVIEW_EXCLUSIONS:
            omitted_review.add(value)
            continue
        native_rules.add((kind, value))
    if not native_rules:
        raise ValueError("empty native rule source")
    return native_rules, omitted_ip, omitted_review


def parse_peter_hosts(data):
    """Explicit HOSTS-to-exact-DOMAIN conversion, fail on unknown content."""
    domains = set()
    for number, raw in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        fields = line.split()
        if len(fields) != 2 or fields[0] not in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
            raise ValueError("unsupported Peter Lowe HOSTS record at line " + str(number))
        domain = fields[1].lower()
        if not DOMAIN.fullmatch(domain):
            raise ValueError("invalid Peter Lowe hostname at line " + str(number))
        domains.add(domain)
    if not domains:
        raise ValueError("empty Peter Lowe source")
    return domains


def build_preview(native_data, peter_data):
    """Return only counts and digest; do not return or publish third-party rules."""
    native, omitted_ip, omitted_review = parse_native(native_data)
    peter_hosts = parse_peter_hosts(peter_data)
    exact = {v for kind, v in native if kind == "DOMAIN"}
    suffix = {v for kind, v in native if kind == "DOMAIN-SUFFIX"}
    keywords = {v for kind, v in native if kind == "DOMAIN-KEYWORD"}

    # Do not reintroduce excluded app-functionality hosts from Peter Lowe.
    peter_extra = {h for h in peter_hosts
                   if h not in REVIEW_EXCLUSIONS and not covered(exact, suffix, h)}
    exact.update(peter_extra)
    for host in KNOWN_GOOD:
        if covered(exact, suffix, host) or any(k in host for k in keywords):
            raise ValueError("known-good host matched by Lite preview")

    # A formerly excluded exact host must not be reblocked by a suffix or
    # keyword. Also refuse a previously unsupported broad rule when promoted.
    for host in REVIEW_EXCLUSIONS:
        if covered(exact, suffix, host) or any(k in host for k in keywords):
            raise ValueError("protected functional host matched by Lite preview")

    lines = sorted({kind + "," + value for kind, value in native} |
                   {"DOMAIN," + host for host in peter_extra})
    if not lines:
        raise ValueError("empty derived preview")
    # This digest is for comparison across runs, not a downloadable list.
    digest = hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()
    return {
        "status": "read-only memory-only preview; NO subscription/export/deployment",
        "native_rules_included": len(native),
        "native_ip_rules_omitted": omitted_ip,
        "native_functionality_rules_omitted": len(omitted_review),
        "peter_exact_domains_unique": len(peter_hosts),
        "peter_exact_domains_added": len(peter_extra),
        "candidate_rules": len(lines),
        "candidate_sha256": digest,
        "known_good_conflicts": 0,
        "sensitive_functionality_conflicts": 0,
        "conversion": "Peter Lowe HOSTS -> Surge DOMAIN, never DOMAIN-SUFFIX",
    }


def main():
    blobs = {name: fetch(name, SOURCES[name]) for name in PINS}
    for name, digest in PINS.items():
        if hashlib.sha256(blobs[name]).hexdigest() != digest:
            raise ValueError(name + " changed since audited snapshot; re-review required")
    result = build_preview(blobs["awavenue_surge_only_ads"],
                           blobs["peter_lowe_ads_only"])
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
