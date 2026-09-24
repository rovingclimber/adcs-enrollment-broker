#!/usr/bin/env python3
"""Fail-closed contracts for repository-owned Semgrep evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


TOOL = Path(__file__).with_name("check-semgrep-sarif.py")
POLICY = Path.cwd() / "security" / "semgrep" / "pkiproxy-security.yml"


def invoke(report: Path, policy_hash: Path, expected: bool) -> None:
    result = subprocess.run([sys.executable, str(TOOL), str(report), str(POLICY), str(policy_hash)],
                            text=True, capture_output=True, check=False)
    if (result.returncode == 0) != expected:
        raise AssertionError(f"unexpected result {result.returncode}: {result.stdout}\n{result.stderr}")


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        report = root / "semgrep.sarif"
        policy_hash = root / "policy.sha256"
        policy_hash.write_text(hashlib.sha256(POLICY.read_bytes()).hexdigest() + "  policy.yml\n", encoding="ascii")
        clean = {"runs": [{"invocations": [{"executionSuccessful": True, "toolExecutionNotifications": []}]}]}
        report.write_text(json.dumps(clean), encoding="utf-8")
        invoke(report, policy_hash, True)
        clean["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [
            {"level": "warning", "message": {"text": "parser warning"}}
        ]
        report.write_text(json.dumps(clean), encoding="utf-8")
        invoke(report, policy_hash, False)
        policy_hash.write_text("0" * 64 + "  policy.yml\n", encoding="ascii")
        invoke(report, policy_hash, False)
    print("Semgrep evidence contracts passed: 3.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
