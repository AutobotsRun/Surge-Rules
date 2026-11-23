#!/usr/bin/env python3
"""Build a one-deletion Hijacking review candidate; never deploy automatically.

Every source row except the specifically audited Adobe service host is
byte-identical to a pinned blackmatrix7 GPL-2.0 Git blob.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

SOURCE_SHA = "0ffb798f0ce5f098fd3e7dc889fbbca94b9bdd5d"
REPO = "blackmatrix7/ios_rule_script"
REMOVED = b"DOMAIN,geo2.adobe.com"
ORIGINAL_COUNT = 228
EXPECTED_COUNT = ORIGINAL_COUNT - 1


def git_blob_sha(raw):
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\0" + raw
    ).hexdigest()


def parse_rules(source):
    seen = set()
    for row in source.splitlines():
        if not row or row.startswith((b"#", b";", b"//")):
            continue
        bits = row.split(b",")
        if (len(bits) not in (2, 3)
                or bits[0] not in (b"DOMAIN", b"DOMAIN-SUFFIX", b"IP-CIDR")
                or not bits[1]):
            raise ValueError("Unexpected Hijacking rule syntax")
        if bits[0] in (b"DOMAIN", b"DOMAIN-SUFFIX") and len(bits) != 2:
            raise ValueError("Unexpected domain flags")
        if bits[0] == b"IP-CIDR" and len(bits) == 3 and bits[2] != b"no-resolve":
            raise ValueError("Unexpected IP flags")
        if row in seen:
            raise ValueError("Duplicated source entry")
        seen.add(row)
    return seen


def build(raw):
    if not raw.endswith(b"\n") or b"\r" in raw:
        raise ValueError("Unexpected upstream line endings")
    if git_blob_sha(raw) != SOURCE_SHA:
        raise ValueError("Pinned upstream source mismatch")
    lines = raw.splitlines(keepends=True)
    original = parse_rules(raw)
    if len(original) != ORIGINAL_COUNT or lines.count(REMOVED + b"\n") != 1:
        raise ValueError("Expected source count or Adobe rule missing")
    kept = [x for x in lines if x != REMOVED + b"\n"]
    if len(parse_rules(b"".join(kept))) != EXPECTED_COUNT:
        raise ValueError("Only one rule may be removed")
    header = (
        b"# TEST ONLY: curated Hijacking (not a deployed subscription)\n"
        b"# Source author: blackmatrix7 / GPL-2.0\n"
        b"# Change: remove exact legitimate Adobe service DOMAIN,geo2.adobe.com\n"
        b"# See bundled THIRD_PARTY_NOTICES.md and LICENSE.GPL-2.0.txt\n"
    )
    payload = header + b"".join(kept)
    manifest = {
        "pinned_git_blob": SOURCE_SHA,
        "original_rules": ORIGINAL_COUNT,
        "curated_rules": EXPECTED_COUNT,
        "single_removed_rule": REMOVED.decode(),
        "candidate_sha256": hashlib.sha256(payload).hexdigest(),
        "license": "GPL-2.0",
        "deployed": False,
    }
    return payload, manifest


def main():
    url = f"https://api.github.com/repos/{REPO}/git/blobs/{SOURCE_SHA}"
    headers = {"User-Agent": "surge-hijacking-research", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    with urlopen(Request(url, headers=headers), timeout=40) as res:
        response = json.load(res)
    if response.get("sha") != SOURCE_SHA or response.get("encoding") != "base64":
        raise ValueError("Unexpected upstream response")
    raw = base64.b64decode(response["content"])
    payload, metadata = build(raw)
    root = Path("/tmp/hijacking-curated-test-only")
    root.mkdir(parents=True, exist_ok=True)
    (root / "Hijacking-Curated-TEST.list").write_bytes(payload)
    (root / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    lic = Path("sources/blackmatrix7/LICENSE")
    if not lic.is_file():
        raise ValueError("GPL-2.0 license missing")
    (root / "LICENSE.GPL-2.0.txt").write_bytes(lic.read_bytes())
    (root / "THIRD_PARTY_NOTICES.md").write_text(
        "# Source and modification\n\n"
        "Original author blackmatrix7, GPL-2.0:\n"
        "https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Surge/Hijacking/Hijacking.list\n\n"
        "Modification: remove the exact geo2.adobe.com rule because Adobe "
        "lists this as an application network endpoint:\n"
        "https://helpx.adobe.com/business/enterprise/manage-services/configure-services/network-endpoints.html\n\n"
        "All other 227 rule predicates and source comments remain unchanged.\n"
        "The user has NOT deployed this test. AdGuard Home independently blocks "
        "this Adobe hostname and is NOT modified here.\n",
        encoding="utf-8"
    )
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
