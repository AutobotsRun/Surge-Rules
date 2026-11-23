#!/usr/bin/env python3
"""Audit external Surge rules without touching Surge devices or profile files.

Default mode (--check): offline validation, suitable for pull requests.
--sync: fetch audited URLs and produce deterministic fingerprints; mirror only
sources explicitly approved in upstreams/catalog.json. Never auto-publish.
"""
import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
CATALOG = ROOT / "upstreams/catalog.json"
STATE = ROOT / "upstreams/state.json"
MAX_SOURCE_BYTES = 32 * 1024 * 1024
RULE_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN",
    "USER-AGENT", "URL-REGEX", "DEST-PORT", "SRC-PORT",
    "PROCESS-NAME", "PROCESS-PATH", "PROTOCOL", "IN-PORT",
    "SRC-IP", "SRC-IP-CIDR", "HOSTNAME-TYPE", "NETWORK",
    "DEVICE-NAME", "SSID", "BSSID", "SUBNET", "CELLULAR-RADIO",
    "DOMAIN-SET", "RULE-SET", "AND", "OR", "NOT",
}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")


def validate_source(source):
    sid = source["id"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", sid):
        raise ValueError("Invalid source id: " + sid)
    url = urllib.parse.urlsplit(source["url"])
    if (url.scheme != "https" or url.hostname != "raw.githubusercontent.com"
            or url.username or url.password or url.port or url.query
            or url.fragment or not url.path.endswith(".list")):
        raise ValueError("Only HTTPS GitHub raw .list URLs are allowed: " + sid)
    parts = url.path.strip("/").split("/")
    if len(parts) < 5 or any(part in ("", ".", "..") for part in parts):
        raise ValueError("Unexpected upstream path: " + sid)
    mode = source["mode"]
    if mode not in ("monitor", "mirror"):
        raise ValueError("Invalid mode for " + sid)
    approved = source["redistribution_approved"]
    if not isinstance(approved, bool):
        raise ValueError("Invalid approval flag: " + sid)
    if mode == "mirror":
        if not approved or not source.get("license") or source["license"] == "UNVERIFIED":
            raise ValueError("Mirroring requires verified license and explicit approval: " + sid)
        if not source.get("license_url"):
            raise ValueError("Mirroring requires original license URL: " + sid)
        path = pathlib.PurePosixPath(source["mirror_path"])
        if (not source["mirror_path"].startswith("upstream/")
                or ".." in path.parts or path.suffix != ".list"):
            raise ValueError("Unsafe mirror path: " + sid)
    elif approved:
        raise ValueError("Monitor entries must not claim redistribution approval: " + sid)


def validate_rules(text, name, strict=False):
    if not text.strip() or "\0" in text or text.lstrip().lower().startswith(("<html", "<!doctype")):
        raise ValueError("Empty/binary/HTML upstream: " + name)
    lines = text.splitlines()
    count = 0
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        count += 1
        if strict:
            kind = line.split(",", 1)[0]
            if kind not in RULE_TYPES or "," not in line:
                raise ValueError("Unrecognized rule at " + name + ":" + str(i) + " (" + kind + ")")
    if count == 0:
        raise ValueError("No rules in " + name)
    return count


def validate_custom():
    path = ROOT / "custom/WeChat-CDN.list"
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            fields = s.split(",")
            if len(fields) != 3 or fields[0] != "IP-CIDR" or fields[2] != "no-resolve":
                raise ValueError("Invalid custom CDN rule: " + s)
            net = ipaddress.ip_network(fields[1], strict=True)
            if net.prefixlen != 32:
                raise ValueError("CDN exceptions must be /32: " + s)
            rows.append(s)
    if not rows or len(rows) != len(set(rows)):
        raise ValueError("Empty or duplicate custom CDN rules")
    print("Verified custom CDN rules:", len(rows))


def validate_catalog():
    data = read_json(CATALOG)
    if data.get("schema") != 1 or not isinstance(data.get("sources"), list):
        raise ValueError("Unsupported catalog schema")
    ids, mirrors = set(), set()
    for source in data["sources"]:
        validate_source(source)
        sid = source["id"]
        if sid in ids:
            raise ValueError("Duplicate source id: " + sid)
        ids.add(sid)
        if source["mode"] == "mirror":
            path = source["mirror_path"]
            if path in mirrors:
                raise ValueError("Duplicate mirror path: " + path)
            mirrors.add(path)
    return data["sources"]


def validate_state(sources):
    if not STATE.exists():
        return {}
    state = read_json(STATE)
    if state.get("schema") != 1:
        raise ValueError("Unsupported state schema")
    entries = {item["id"]: item for item in state["sources"]}
    if len(entries) != len(state["sources"]):
        raise ValueError("Duplicate state id")
    if set(entries) != {item["id"] for item in sources}:
        raise ValueError("State/catalog source list mismatch; run audit")
    for source in sources:
        entry = entries[source["id"]]
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("Malformed fingerprint: " + source["id"])
        if source["mode"] == "mirror":
            path = ROOT / source["mirror_path"]
            if not path.is_file():
                raise ValueError("Missing mirror file: " + str(path))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != entry["sha256"]:
                raise ValueError("Mirror and approved state differ: " + source["id"])
    return entries


def download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Surge-Rules-Auditor/1.0"})
    with urllib.request.urlopen(req, timeout=45) as response:
        target = urllib.parse.urlsplit(response.geturl())
        if target.scheme != "https" or target.hostname != "raw.githubusercontent.com":
            raise ValueError("Unexpected redirect host")
        data = response.read(MAX_SOURCE_BYTES + 1)
    if not data or len(data) > MAX_SOURCE_BYTES:
        raise ValueError("Source empty or exceeds 32 MiB cap")
    return data, data.decode("utf-8-sig", errors="strict")


def sync(sources, old, report_path):
    staged = []
    changes = []
    for source in sources:
        sid = source["id"]
        data, text = download(source["url"])
        count = validate_rules(text, sid, strict=source["mode"] == "mirror")
        previous = old.get(sid)
        if previous and previous.get("lines", 0) >= 100 and count < previous["lines"] * 0.5:
            raise ValueError("Sudden >50% drop in rules for " + sid + "; inspect upstream manually")
        item = {"id": sid, "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data), "lines": count}
        staged.append((source, data, item))
        if not previous or previous["sha256"] != item["sha256"]:
            changes.append((sid, source["mode"], previous, item, source["url"]))
        print("Audited", sid, item["lines"], "rules")
    # All fetches and checks must succeed before any tracked file is changed.
    for source, data, item in staged:
        if source["mode"] == "mirror":
            path = ROOT / source["mirror_path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    write_json(STATE, {"schema": 1, "sources": [entry for _, _, entry in staged]})
    report = [
        "## External rule audit (human review required)",
        "",
        "This pull request **does not update any Surge device**. It only changes "
        "source fingerprints and explicitly approved mirrors.",
        "",
        "No merge is automatic. For monitor-only sources, inspect the original "
        "upstream diff; a fingerprint change is not a content diff.",
        "",
        "| Source | Mode | Previous SHA256 | Current SHA256 | Rules |",
        "| --- | --- | --- | --- | ---: |",
    ]
    for sid, mode, prev, new, url in changes:
        previous = prev["sha256"][:12] if prev else "(baseline)"
        report.append("| [" + sid + "](" + url + ") | " + mode + " | "
                      + previous + " | " + new["sha256"][:12] + " | "
                      + str(new["lines"]) + " |")
    if not changes:
        report.append("| — | — | No changes | — | — |")
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("Changed sources:", len(changes))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sync", action="store_true", help="Fetch upstream and stage review-only state")
    parser.add_argument("--report", type=pathlib.Path,
                        default=pathlib.Path("/tmp/surge-upstreams-report.md"))
    args = parser.parse_args()
    sources = validate_catalog()
    validate_custom()
    prior = validate_state(sources)
    if args.sync:
        sync(sources, prior, args.report)
    else:
        print("Offline validation OK:", len(sources), "upstreams")


if __name__ == "__main__":
    main()
