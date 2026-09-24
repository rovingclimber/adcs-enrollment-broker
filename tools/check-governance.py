#!/usr/bin/env python3
"""Fail closed when a public candidate omits its governance boundary."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys


APACHE_2_LICENSE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
EXPECTED_NOTICE = (
    "AD CS Enrollment Broker\n"
    "Copyright 2026 RovingClimber\n"
    "\n"
    "This product includes software developed for the AD CS Enrollment Broker project.\n"
)


REQUIRED = {
    "LICENSE": ("Apache License", "Version 2.0, January 2004"),
    "NOTICE": ("AD CS Enrollment Broker", "Copyright 2026 RovingClimber"),
    "SECURITY.md": ("private vulnerability-reporting", "Supported versions", "Published lab-PoC boundary", "descriptor-bound"),
    "SUPPORT.md": ("Outside the support boundary", "SECURITY.md", "isolated lab PoC"),
    "CONTRIBUTING.md": ("Apache-2.0 `LICENSE`", "CI must never deploy"),
    "GOVERNANCE.md": ("repository owner", "Automation may build"),
    "THIRD_PARTY_NOTICES.md": ("SPDX", "does not redistribute specification PDFs"),
    "RELEASE_CHECKLIST.md": ("history-free", "external security review", "authoritative for file modes"),
    "docs/security/release-governance.md": ("unsigned hash chain", "mirrored without edits"),
}


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    failures: list[str] = []
    for relative, markers in REQUIRED.items():
        path = root / relative
        if not path.is_file():
            failures.append(f"missing governance artifact: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                failures.append(f"{relative} lacks required marker: {marker}")

    license_path = root / "LICENSE"
    if license_path.is_file():
        actual = hashlib.sha256(license_path.read_bytes()).hexdigest()
        if actual != APACHE_2_LICENSE_SHA256:
            failures.append("LICENSE is not the approved unmodified Apache-2.0 text")

    notice_path = root / "NOTICE"
    if notice_path.is_file() and notice_path.read_text(encoding="utf-8") != EXPECTED_NOTICE:
        failures.append("NOTICE differs from the approved minimal attribution")

    if failures:
        print("public governance check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Public governance artifacts passed with approved Apache-2.0 LICENSE and NOTICE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
