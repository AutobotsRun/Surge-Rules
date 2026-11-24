#!/usr/bin/env python3
"""Reproduce reviewed GPL-2.0 service RULE-SET files from audited snapshots.

Only a provenance header is added. Matching predicates, order, complex rules,
IP ranges, process/user-agent expressions, and case are preserved byte-for-byte.
--check is offline/read-only; --write builds candidates only for GitHub review.
"""
import argparse
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = pathlib.Path("config/managed-services.json")
CATALOG = pathlib.Path("upstreams/catalog.json")
STATE = pathlib.Path("upstreams/state.json")
LICENSE = pathlib.Path("sources/blackmatrix7/LICENSE")
SOURCE_REPO = "https://github.com/blackmatrix7/ios_rule_script"
KNOWN_NAMES = {"Google", "YouTube", "Apple", "OpenAI", "Telegram", "Netflix", "Spotify", "HBO", "Amazon", "Disney", "ParamountPlus", "Peacock", "Reddit", "PayPal", "Sina"}
RULE_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "USER-AGENT", "PROCESS-NAME",
    "PROCESS-PATH", "URL-REGEX", "OR", "AND", "NOT", "GEOIP",
}


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def safe_file(root, relative, prefix):
    if not isinstance(relative, str):
        raise ValueError("Not a relative path: " + str(relative))
    p = pathlib.PurePosixPath(relative)
    if (p.is_absolute() or not p.parts or p.parts[0] != prefix
            or ".." in p.parts or ".git" in p.parts
            or p.suffix != ".list"):
        raise ValueError("Invalid managed path: " + relative)
    path = root
    for part in p.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Refuse symlink path: " + relative)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Path escapes repository: " + relative)
    return path


def source_rules(raw, name):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Not UTF-8: " + name) from exc
    if not text or "\0" in text or text.lstrip().lower().startswith(("<html", "<!doctype")):
        raise ValueError("Unexpected source data: " + name)
    rows = []
    for num, row in enumerate(text.splitlines(), 1):
        item = row.strip()
        if not item or item.startswith(("#", ";", "//")):
            continue
        kind = item.split(",", 1)[0]
        if kind not in RULE_TYPES or "," not in item:
            raise ValueError(f"Unreviewed rule type {kind} in {name}:{num}")
        rows.append(item)
    if not rows or len(rows) != len(set(rows)):
        raise ValueError("Empty or duplicate active rules: " + name)
    return rows


def build_outputs(root=ROOT):
    manifest = load_json(root / MANIFEST)
    catalog = load_json(root / CATALOG)
    state = load_json(root / STATE)
    if (manifest.get("schema") != 1
            or manifest.get("license") != "GPL-2.0"
            or manifest.get("license_file") != LICENSE.as_posix()
            or manifest.get("source_repo") != SOURCE_REPO):
        raise ValueError("Unexpected managed-services manifest")
    if not (root / LICENSE).is_file():
        raise ValueError("Missing redistributed upstream GPL-2.0 license")
    sources = {x["id"]: x for x in catalog["sources"]}
    snapshots = {x["id"]: x for x in state["sources"]}
    declared = manifest.get("services")
    if not isinstance(declared, list) or len(declared) != len(KNOWN_NAMES):
        raise ValueError("Expected exactly fifteen reviewed services")
    names, paths, outputs = set(), set(), {}
    for service in declared:
        name = service["name"]
        sid = service["id"]
        mirror = service["mirror_path"]
        published = service["published_path"]
        if name not in KNOWN_NAMES or name in names:
            raise ValueError("Unexpected or duplicate service: " + name)
        names.add(name)
        if not sid.startswith("blackmatrix7-"):
            raise ValueError("Unexpected source identity: " + sid)
        if published != f"rules/{name}.list" or published in paths:
            raise ValueError("Unexpected or duplicate published path: " + published)
        paths.add(published)
        src = sources.get(sid)
        record = snapshots.get(sid)
        if not src or not record:
            raise ValueError("Missing audited source/state: " + sid)
        if (src.get("mode") != "mirror" or src.get("redistribution_approved") is not True
                or src.get("license") != "GPL-2.0"
                or src.get("license_url") != SOURCE_REPO + "/blob/master/LICENSE"
                or src.get("mirror_path") != mirror
                or record.get("mode") != "mirror"
                or record.get("mirror_path") != mirror):
            raise ValueError("Unapproved or mismatched mirror: " + sid)
        if not src["url"].startswith(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
        ):
            raise ValueError("Unexpected upstream host: " + sid)
        if mirror != f"upstream/blackmatrix7/{pathlib.PurePosixPath(mirror).name}":
            raise ValueError("Unexpected mirror directory: " + sid)
        mirror_path = safe_file(root, mirror, "upstream")
        safe_file(root, published, "rules")
        data = mirror_path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        active = source_rules(data, sid)
        if (digest != record["sha256"] or len(data) != record["bytes"]
                or len(active) != record["lines"]):
            raise ValueError("Snapshot differs from audited fingerprint: " + sid)
        floor = service.get("baseline_rules")
        if type(floor) is not int or floor < 1 or len(active) * 2 < floor:
            raise ValueError("Unexpected >50% rules decrease: " + sid)
        header = (
            "# GENERATED managed rule-set; do not edit directly.\n"
            "# Derived from blackmatrix7/ios_rule_script (GPL-2.0).\n"
            f"# Original: {src['url']}\n"
            "# License text: sources/blackmatrix7/LICENSE\n"
            "# Local change 2026-11-23: added this provenance header; rule predicates unchanged.\n"
            "# Matching policy is assigned by the calling Surge RULE-SET.\n"
            "\n"
        )
        outputs[published] = header.encode("utf-8") + data
    if names != KNOWN_NAMES:
        raise ValueError("Managed-services catalog is incomplete")
    return outputs


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Check published files byte for byte")
    mode.add_argument("--write", action="store_true", help="Generate files for reviewed GitHub PR")
    args = parser.parse_args()
    outputs = build_outputs(ROOT)
    if args.check:
        for relative, data in outputs.items():
            path = ROOT / relative
            if not path.is_file() or path.read_bytes() != data:
                raise ValueError("Generated rule-set differs from reviewed mirror: " + relative)
    else:
        for relative, data in outputs.items():
            path = ROOT / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print(f"Managed service rule-sets {'verified' if args.check else 'generated'}: {len(outputs)}")


if __name__ == "__main__":
    main()
