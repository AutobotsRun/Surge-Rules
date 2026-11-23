#!/usr/bin/env python3
"""Verify the research-only Safari safety compatibility candidate.

Fetches the SHA-pinned public Privacy Git blob (read-only), validates its Git
object digest, verifies exact source-preserving transformation and the
one-host AdGuard allowlist proposal. Does not deploy or alter devices/DNS.
"""
import base64
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen
import os

SOURCE_REPO = "blackmatrix7/ios_rule_script"
SOURCE_SHA = "a75df944a7a0fcae26f762059c0f7fd72f42c420"
CANDIDATE = Path("experiments/privacy-curated/Privacy-Safari-TEST.list")
ADGUARD = Path("adguard/allowlist.txt")
DELETE = (
    b"DOMAIN,safebrowsing.googleapis.com",
    b"DOMAIN,safebrowsing.urlsec.qq.com",
)
KEEP_ALLOW = (
    "@@||apd-pcdnwxlogin.teg.tencent-cloud.net^",
    "@@||apd-pcdnwxstat.teg.tencent-cloud.net^",
    "@@||dns.weixin.qq.com.cn^",
    "@@||smartpay-admin.fugetech.com^",
)
TENCENT_ALLOW = "@@||safebrowsing.urlsec.qq.com^"


def active_lines(raw):
    return [s.strip() for s in raw.splitlines() if s.strip()
            and not s.strip().startswith((b"#", b"!", b";", b"//"))]


def verify(source: bytes, candidate: bytes, allowlist: str) -> dict:
    source_rows = source.splitlines(keepends=True)
    original = active_lines(source)
    if len(original) != 39936 or len(original) != len(set(original)):
        raise ValueError("Unreviewed source rule count or duplicate")
    if len(candidate) < 1000 or not candidate.startswith(
            b"# RESEARCH ONLY"):
        raise ValueError("Missing explicit nonproduction notice")
    if b"# NAME: Privacy\n" not in source:
        raise ValueError("Unexpected upstream header")
    if candidate.count(b"# NAME: Privacy\n") != 1:
        raise ValueError("Expected exactly one original upstream header")
    for rule in DELETE:
        if source_rows.count(rule + b"\n") != 1:
            raise ValueError("Source deletion target does not occur exactly once")
        if (rule + b"\n") in candidate[candidate.index(b"# NAME: Privacy\n"):]:
            raise ValueError("Candidate still has deleted active rule")
    # The candidate's first section consists solely of provenance comments.
    original_start = candidate.index(b"# NAME: Privacy\n")
    prefix = candidate[:original_start]
    if active_lines(prefix):
        raise ValueError("Provenance header unexpectedly contains rules")
    expected_body = b"".join(row for row in source_rows
                             if row not in {rule + b"\n" for rule in DELETE})
    if candidate[original_start:] != expected_body:
        raise ValueError("Candidate differs from upstream in another byte")
    if len(active_lines(candidate)) != 39934:
        raise ValueError("Unexpected candidate active count")
    if b"GPL-2.0" not in prefix:
        raise ValueError("Missing GPL-2.0 notice")
    if not Path("sources/blackmatrix7/LICENSE").is_file():
        raise ValueError("Missing GPL license in repository")

    entries = [s.strip() for s in allowlist.splitlines()
               if s.strip() and not s.strip().startswith(("#", "!", ";"))]
    if sorted(entries) != sorted((*KEEP_ALLOW, TENCENT_ALLOW)):
        raise ValueError("AdGuard allowlist differs from exactly five expected exceptions")
    if entries.count(TENCENT_ALLOW) != 1:
        raise ValueError("Tencent AdGuard exception absent or duplicated")
    return {
        "source_git_blob": SOURCE_SHA,
        "original_rules": len(original),
        "candidate_rules": len(active_lines(candidate)),
        "deleted_exact_rules": [x.decode() for x in DELETE],
        "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
        "adguard_allow_count": len(entries),
        "no_network_or_device_changes": True,
    }


def fetch_source() -> bytes:
    url = f"https://api.github.com/repos/{SOURCE_REPO}/git/blobs/{SOURCE_SHA}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "surge-safari-compat-research",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urlopen(Request(url, headers=headers), timeout=45) as response:
        meta = json.load(response)
    if meta.get("sha") != SOURCE_SHA or meta.get("encoding") != "base64":
        raise ValueError("Unexpected upstream Git object metadata")
    raw = base64.b64decode(meta["content"])
    actual = hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\0" + raw
    ).hexdigest()
    if actual != SOURCE_SHA:
        raise ValueError("Upstream Git blob hash mismatch")
    return raw


if __name__ == "__main__":
    result = verify(fetch_source(), CANDIDATE.read_bytes(),
                    ADGUARD.read_text(encoding="utf-8"))
    print(json.dumps(result, ensure_ascii=False, indent=2))
