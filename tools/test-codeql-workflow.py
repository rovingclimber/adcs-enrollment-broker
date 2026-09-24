#!/usr/bin/env python3
"""Fail-closed structural checks for the public CodeQL workflow."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")
    require("branches: [main]" in text and "gh-pages" not in text,
            "CodeQL must scan source branches, never generated Pages output")
    require("build-mode: manual" in text and "dotnet restore PkiProxy.slnx --locked-mode" in text,
            "CodeQL must trace an explicit locked build")
    require("queries: security-extended" in text and "threat-models: local" in text,
            "advanced setup must preserve the stronger default-setup policy")
    require("security-events: write" in text and "contents: read" in text,
            "CodeQL permissions changed")
    require("github.event.pull_request.head.repo.full_name == github.repository" in text,
            "untrusted fork pull requests must not receive upload authority")
    action_refs = re.findall(r"^\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
    require(action_refs and all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) for ref in action_refs),
            "every CodeQL workflow action must use an immutable commit")
    print("CodeQL workflow contracts passed: 6.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
