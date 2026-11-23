#!/usr/bin/env python3
"""Build a GPL-noticed, TEST-ONLY Surge RULE-SET artifact in /tmp.

NOT a production subscription: never writes to rules/ or pushes to GitHub.
Run only on explicitly pinned, previously audited upstream snapshots.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from preview_advertising_lite import PINS, _assemble_candidate
from research_advertising_lite import SOURCES, fetch

AWA_LICENSE = "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/LICENSE"
EXPECTED_RULE_COUNT = 2890
EXPECTED_CANONICAL_SHA256 = "92cdd3dd0eed603d9eb153fed92b06ef8dd9d21ef949df883ac29c098ffdf632"
OUTPUT = Path("/tmp/advertising-lite-surge-test-only")
TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}


def verify_license(text):
    """Require a full upstream GPL-3 license, not a link or a short excerpt."""
    if ("GNU GENERAL PUBLIC LICENSE" not in text
            or "Version 3, 29 June 2007" not in text
            or "END OF TERMS AND CONDITIONS" not in text
            or len(text.encode("utf-8")) < 12000):
        raise ValueError("AWAvenue full upstream GPL-3 license is missing or invalid")


def verify_rules(lines, manifest):
    """Strict linter for every rule: Surge skips malformed rules with warnings."""
    if len(lines) != EXPECTED_RULE_COUNT or len(lines) != len(set(lines)):
        raise ValueError("unexpected rule count or duplicates")
    if lines != sorted(lines):
        raise ValueError("rules not in deterministic order")
    for number, line in enumerate(lines, 1):
        parts = line.split(",")
        if len(parts) != 2 or parts[0] not in TYPES:
            raise ValueError("invalid Surge RULE-SET rule at line " + str(number))
        if not parts[1] or any(ch.isspace() for ch in parts[1]):
            raise ValueError("invalid rule value at line " + str(number))
    canonical = "\n".join(lines) + "\n"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if digest != EXPECTED_CANONICAL_SHA256 or digest != manifest["candidate_sha256"]:
        raise ValueError("unreviewed candidate hash")
    if manifest["candidate_rules"] != EXPECTED_RULE_COUNT:
        raise ValueError("unexpected preview metadata")
    if manifest["native_ip_rules_omitted"] != 13:
        raise ValueError("unexpected IP rule quarantine count")
    if manifest["native_functionality_rules_omitted"] != 8:
        raise ValueError("unexpected functionality quarantine count")
    return canonical


def provenance_note(manifest):
    return (
        "# Advertising Lite TEST ONLY; not a production subscription\n"
        "# Variant: safety-first, exact Peter Lowe hosts; no unreviewed IP rules\n"
        "# AWAvenue Only.Ads source: " + SOURCES["awavenue_surge_only_ads"] + "\n"
        "# AWAvenue license: GNU GPL version 3; full text in LICENSE.GPL-3.0.txt\n"
        "# Peter Lowe source: " + SOURCES["peter_lowe_ads_only"] + "\n"
        "# Peter Lowe permission: https://pgl.yoyo.org/as/ (about this list)\n"
        "# Attribution and changes: THIRD_PARTY_NOTICES.md\n"
        "# Canonical SHA256 of rule lines (excludes header): " + manifest["candidate_sha256"] + "\n"
        "# Lines: 2890; 13 native IP entries and 8 exact functionality candidates omitted\n"
        "# Do not enable simultaneously with the current full Advertising RULE-SET.\n"
    )


def build_files(native_bytes, peter_bytes, license_text):
    """Return a dict of UTF-8 files; no I/O and no network in unit tests."""
    verify_license(license_text)
    lines, manifest = _assemble_candidate(native_bytes, peter_bytes)
    canonical = verify_rules(lines, manifest)
    rule_file = provenance_note(manifest) + canonical
    rules_file_sha = hashlib.sha256(rule_file.encode("utf-8")).hexdigest()
    notice = (
        "# THIRD-PARTY NOTICES — Advertising Lite TEST ONLY\n\n"
        "This experimental bundle combines third-party entries, including derived AWAvenue rules. "
        "It is not original-only content and is not an upstream-endorsed release.\n\n"
        "## AWAvenue — TG-Twilight and contributors\n\n"
        "- Project: https://github.com/TG-Twilight/AWAvenue-Ads-Rule\n"
        "- Audited source: " + SOURCES["awavenue_surge_only_ads"] + "\n"
        "- Original license: GNU General Public License version 3. "
        "The accompanying LICENSE.GPL-3.0.txt reproduces the upstream full license.\n"
        "- Modifications: omit 13 IP-CIDR rules while awaiting IP ownership review; "
        "quarantine 8 exact potential functionality endpoints; sort, deduplicate "
        "and combine only supported domain/keyword entries. These exclusions are "
        "precautionary, not proven upstream bugs.\n\n"
        "## Peter Lowe\n\n"
        "- Project and reuse permission: https://pgl.yoyo.org/as/\n"
        "- List selection: " + SOURCES["peter_lowe_ads_only"] + "\n"
        "- Original author explicitly permits merging the list with other sources "
        "and publishing the combination.\n"
        "- Modifications: convert HOSTS names to exact Surge DOMAIN rules, "
        "deduplicate against retained native domain/suffix predicates, and avoid "
        "introducing the eight quarantined hosts.\n\n"
        "## Integrity, safety and reproducibility\n\n"
        "- Upstream input SHA256 pinned in scripts/preview_advertising_lite.py.\n"
        "- Deterministic rules SHA256 (without comment header): " +
        manifest["candidate_sha256"] + "\n"
        "- Output list SHA256 (with comment header): " + rules_file_sha + "\n"
        "- This is a static, non-auto-updating snapshot.\n"
        "- Public research, tests and source code: "
        "https://github.com/AutobotsRun/Surge-Rules/pull/12\n"
        "- This artifact is a prototype for a spare-device A/B test, not "
        "a recommendation for production use; existing Surge and AdGuard Home "
        "configurations are not changed by this build.\n"
    )
    manifest = dict(manifest)
    manifest.update({
        "artifact_purpose": "TEST ONLY, generated on GitHub Actions; not published as subscription",
        "list_sha256": rules_file_sha,
        "source_sha256": dict(PINS),
        "rule_file_name": "Advertising-Lite-TEST.list",
        "rule_syntax": "Surge external RULE-SET (not DOMAIN-SET)",
        "license_file_name": "LICENSE.GPL-3.0.txt",
    })
    return {
        "Advertising-Lite-TEST.list": rule_file,
        "LICENSE.GPL-3.0.txt": license_text,
        "THIRD_PARTY_NOTICES.md": notice,
        "manifest.json": json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
    }


def main():
    if OUTPUT.exists():
        raise ValueError("test-only output directory already exists; refusing overwrite")
    blobs = {key: fetch(key, SOURCES[key]) for key in PINS}
    for key in PINS:
        if hashlib.sha256(blobs[key]).hexdigest() != PINS[key]:
            raise ValueError("upstream snapshot changed: " + key)
    license_text = fetch("awavenue_gpl", AWA_LICENSE).decode("utf-8")
    files = build_files(blobs["awavenue_surge_only_ads"],
                        blobs["peter_lowe_ads_only"], license_text)
    # Restrict writes to our fixed ephemeral test folder. Never create rules/*.
    with tempfile.TemporaryDirectory(prefix="lite-stage-", dir="/tmp") as stage:
        root = Path(stage)
        for name, data in files.items():
            (root / name).write_text(data, encoding="utf-8")
        OUTPUT.mkdir(mode=0o700)
        for name in files:
            (root / name).replace(OUTPUT / name)
    manifest = json.loads(files["manifest.json"])
    print(json.dumps({
        "artifact_directory": str(OUTPUT),
        "candidate_rules": manifest["candidate_rules"],
        "candidate_sha256": manifest["candidate_sha256"],
        "with_header_file_sha256": manifest["list_sha256"],
        "license_and_source_notices": True,
        "effect": "offline artifact only; NO deployment; NO production RULE-SET"
    }, sort_keys=True))


if __name__ == "__main__":
    main()
