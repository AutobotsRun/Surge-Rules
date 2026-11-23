#!/usr/bin/env python3
"""Build a fail-closed, single-deletion Privacy test candidate.

Public upstream GPL-2.0 list; read pinned Git blob only. This script must not
write profile data, deploy rules, update production, or modify AdGuard Home.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import urllib.request

REPO = "blackmatrix7/ios_rule_script"
SOURCE_SHA = "a75df944a7a0fcae26f762059c0f7fd72f42c420"
SOURCE_URL = "https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Surge/Privacy/Privacy_All.list"
TARGET = b"DOMAIN,safebrowsing.googleapis.com"
BASELINE_COUNT = 39_936
EXPECTED_COUNT = BASELINE_COUNT - 1
HEADER = (
    "# PRIVACY CURATED TEST ONLY — not a production subscription\n"
    "# Origin: blackmatrix7/ios_rule_script, GPL-2.0\n"
    "# Original source: " + SOURCE_URL + "\n"
    "# Pinned Git blob: " + SOURCE_SHA + "\n"
    "# Change: remove exactly one overblocking DOMAIN,safebrowsing.googleapis.com entry\n"
    "# Unmodified upstream source bytes retained after this added notice, except for that one line\n"
    "# License: sources/blackmatrix7/LICENSE (included in test archive)\n"
    "# Behavior: use Google.list later in Surge rule order for *.googleapis.com\n"
    "# No other Privacy rules intentionally removed; separately review DNS filtering\n"
).encode("utf-8")


def git_blob_hash(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def parse_active(lines: list[bytes]) -> list[bytes]:
    result = []
    permitted = {
        b"DOMAIN", b"DOMAIN-SUFFIX", b"DOMAIN-KEYWORD",
        b"IP-CIDR", b"IP-CIDR6",
    }
    for row in lines:
        line = row.strip()
        if not line or line.startswith((b"#", b"!", b";", b"//")):
            continue
        parts = line.split(b",")
        if len(parts) < 2 or parts[0] not in permitted or not parts[1]:
            raise ValueError("Unexpected rule syntax; refuse generation")
        if parts[0] in {b"DOMAIN", b"DOMAIN-SUFFIX", b"DOMAIN-KEYWORD"}:
            if len(parts) != 2:
                raise ValueError("Unexpected domain rule flags")
        else:
            if len(parts) > 3 or (len(parts) == 3 and parts[2] != b"no-resolve"):
                raise ValueError("Unexpected IP rule flags")
        result.append(line)
    if len(result) != len(set(result)):
        raise ValueError("Duplicate source rule; refuse generation")
    return result


def curate(source: bytes) -> tuple[bytes, dict]:
    if not source or b"\r" in source or not source.endswith(b"\n"):
        raise ValueError("Source must be LF-terminated UTF-8")
    source.decode("utf-8")
    if git_blob_hash(source) != SOURCE_SHA:
        raise ValueError("Source Git blob changed; review required")
    rows = source.splitlines(keepends=True)
    before = parse_active(rows)
    if len(before) != BASELINE_COUNT or rows.count(TARGET + b"\n") != 1:
        raise ValueError("Wrong Privacy version, count, or missing exact exception")
    if b"DOMAIN,safebrowsing.urlsec.qq.com\n" not in rows:
        raise ValueError("Unexpected source: Tencent rule missing")
    # Preserve all source comments and 39,935 other rules byte-for-byte.
    after_rows = [row for row in rows if row != TARGET + b"\n"]
    after = parse_active(after_rows)
    if len(after) != EXPECTED_COUNT or set(before) - set(after) != {TARGET}:
        raise ValueError("Curated delta is not exactly one rule")
    payload = HEADER + b"".join(after_rows)
    metadata = {
        "source_git_blob_sha": SOURCE_SHA,
        "source_url": SOURCE_URL,
        "license": "GPL-2.0",
        "upstream_rule_count": BASELINE_COUNT,
        "curated_rule_count": EXPECTED_COUNT,
        "deleted_rule": TARGET.decode("ascii"),
        "candidate_sha256": hashlib.sha256(payload).hexdigest(),
        "unchanged_source_body_sha256": hashlib.sha256(source).hexdigest(),
        "target_for_testing": "spare iPhone 15 Pro only; NOT ACTIVE",
    }
    return payload, metadata


def fetch() -> bytes:
    url = "https://api.github.com/repos/" + REPO + "/git/blobs/" + SOURCE_SHA
    headers = {"User-Agent": "surge-rules-privacy-audit", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=40) as r:
        record = json.load(r)
    if record.get("encoding") != "base64" or record.get("sha") != SOURCE_SHA:
        raise ValueError("Unexpected Git blob metadata")
    raw = base64.b64decode(record["content"], validate=False)
    if git_blob_hash(raw) != SOURCE_SHA:
        raise ValueError("Git blob integrity check failed")
    return raw


def main() -> None:
    original = fetch()
    new, manifest = curate(original)
    output = Path("/tmp/privacy-curated-test-only")
    output.mkdir(parents=True, exist_ok=True)
    (output / "Privacy-Curated-TEST.list").write_bytes(new)
    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    license_file = Path("sources/blackmatrix7/LICENSE")
    if not license_file.is_file():
        raise ValueError("Missing existing upstream GPL-2.0 license")
    (output / "LICENSE.GPL-2.0.txt").write_bytes(license_file.read_bytes())
    notices = (
        "# Third-party source and changes\n\n"
        "Author: blackmatrix7 (https://github.com/blackmatrix7/ios_rule_script)\n\n"
        "Original: " + SOURCE_URL + "\n\n"
        "License: GPL-2.0, included in LICENSE.GPL-2.0.txt.\n\n"
        "Change: exactly one official Google Safe Browsing API domain entry was\n"
        "removed from the upstream Privacy denylist. The other 39,935 active\n"
        "rules, original comments and rule order are preserved.\n"
        "This is a review-only candidate, not the deployed Surge subscription.\n"
    )
    (output / "THIRD_PARTY_NOTICES.md").write_text(notices, encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
