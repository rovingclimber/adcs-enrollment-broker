#!/usr/bin/env python3
"""Reject incomplete or unsuccessful Semgrep SARIF execution."""

import hashlib
import json
import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: check-semgrep-sarif.py SARIF POLICY POLICY_SHA256")
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    policy_path = Path(sys.argv[2])
    policy_bytes = policy_path.read_bytes()
    digest_fields = Path(sys.argv[3]).read_text(encoding="ascii").split()
    if not digest_fields or digest_fields[0] != hashlib.sha256(policy_bytes).hexdigest():
        raise SystemExit("Semgrep policy digest does not match the scanned policy")
    policy_ids = re.findall(r"(?m)^\s*- id: (pkiproxy\.[a-z0-9.-]+)\s*$", policy_bytes.decode("utf-8"))
    if len(policy_ids) != 15 or len(set(policy_ids)) != 15:
        raise SystemExit("Semgrep policy does not contain the complete unique rule inventory")
    runs = report.get("runs")
    if not isinstance(runs, list) or not runs:
        raise SystemExit("Semgrep SARIF contains no runs")
    failures: list[str] = []
    invocations = 0
    for run in runs:
        for invocation in run.get("invocations", []):
            invocations += 1
            if invocation.get("executionSuccessful") is not True:
                failures.append("scanner execution was not successful")
            for notice in invocation.get("toolExecutionNotifications", []):
                if notice.get("level") in {"warning", "error"}:
                    message = notice.get("message", {}).get("text", "scanner warning")
                    failures.append(message.splitlines()[0])
    if invocations == 0:
        failures.append("Semgrep SARIF contains no invocation record")
    if failures:
        for failure in failures:
            print(f"semgrep execution failure: {failure}", file=sys.stderr)
        return 1
    print(f"Semgrep execution was complete and warning-free with {len(policy_ids)} repository-owned rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
