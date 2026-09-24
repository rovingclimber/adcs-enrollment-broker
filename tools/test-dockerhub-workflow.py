#!/usr/bin/env python3
"""Fail-closed structural checks for the public Docker Hub release workflow."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "container.yml"
DOCKERFILE = ROOT / "Dockerfile"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    require("pull_request_target" not in text, "privileged pull_request_target is forbidden")
    require("types: [published]" in text, "publication must require a published GitHub release")
    require(text.count("if: github.event_name == 'release'") == 4,
            "validation, login, push and attestation must stay release-gated")
    require("IMAGE_NAME: rovingclimber/adcs-enrollment-broker" in text,
            "the workflow must publish to the real public Docker Hub repository")
    require("example/adcs-enrollment-broker" not in text,
            "placeholder image repositories are forbidden")
    require("fetch-depth: 0" in text and "git merge-base --is-ancestor" in text,
            "release source must be proven reachable from main")
    require("^v?[0-9]+\\.[0-9]+\\.[0-9]+$" in text and
            "RELEASE_PRERELEASE" in text,
            "only stable semantic-version releases may publish")
    require("secrets.DOCKERHUB_USERNAME" in text and "secrets.DOCKERHUB_TOKEN" in text,
            "Docker Hub credentials must come from GitHub secrets")
    require("aquasec/trivy:0.73.0@sha256:" in text,
            "the vulnerability scanner must remain digest pinned")
    require(text.index("Scan the exact local image") < text.index("Log in to Docker Hub") <
            text.index("Push the exact scanned image") < text.index("Attest the published image"),
            "scan, login, push and attestation order changed")
    action_refs = re.findall(r"^\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
    require(action_refs and all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) for ref in action_refs),
            "every GitHub Action must use an immutable commit")
    require("platforms: linux/amd64" in text, "the published platform boundary must be explicit")
    require("[ \"$ready\" = 503 ]" in text, "credential-free readiness must fail closed")
    require("COPY lab/device-facts/ lab/device-facts/" in dockerfile and
            "COPY smoke/ smoke/" in dockerfile,
            "the in-image contract run must include its public fixtures")
    print("Docker Hub workflow contracts passed: 14.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
