#!/usr/bin/env python3
"""Adversarial contracts for the runtime image assurance evidence gate."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


TOOL = Path(__file__).with_name("check-runtime-image-scan.py")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write(path: Path, value: object) -> None:
    path.write_bytes(canonical(value))


def invoke(root: Path, expected: bool) -> None:
    result = subprocess.run([
        sys.executable, str(TOOL), "--report", str(root / "report.json"),
        "--image-archive", str(root / "image.tar"), "--image-digest", str(root / "digest.txt"),
        "--provenance", str(root / "provenance.json"), "--scanner-version", str(root / "version.txt"),
        "--scanner-reference", "scanner.invalid/trivy@sha256:" + "7" * 64,
        "--output", str(root / "evidence.json"),
    ], text=True, capture_output=True, check=False)
    if (result.returncode == 0) != expected:
        raise AssertionError(f"unexpected result {result.returncode}: {result.stdout}\n{result.stderr}")


def make_archive(path: Path, config: dict) -> str:
    config_bytes = canonical(config)
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    manifest = canonical([{"Config": config_digest + ".json", "RepoTags": ["fixture:scan"], "Layers": []}])
    with tarfile.open(path, "w") as archive:
        for name, content in (("manifest.json", manifest), (config_digest + ".json", config_bytes)):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mtime = 0
            archive.addfile(member, io.BytesIO(content))
    return config_digest


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        commit = "1" * 40
        provenance = {"schemaVersion": 1, "commit": commit, "buildFiles": []}
        write(root / "provenance.json", provenance)
        provenance_hash = hashlib.sha256((root / "provenance.json").read_bytes()).hexdigest()
        config = {"config": {"User": "1654:1654", "Labels": {
            "org.opencontainers.image.revision": commit,
            "org.example.pki-proxy.provenance-sha256": provenance_hash,
        }}}
        config_digest = make_archive(root / "image.tar", config)
        report = {
            "SchemaVersion": 2, "ArtifactName": "image.tar", "ArtifactType": "container_image",
            "Metadata": {"ImageID": "sha256:" + config_digest, "OS": {"Family": "ubuntu", "Name": "24.04"}},
            "Results": [
                {"Target": "ubuntu", "Class": "os-pkgs", "Type": "ubuntu", "Packages": [{"Name": "libc6", "Version": "1"}]},
                {"Target": "app/PkiProxy.Api.deps.json", "Class": "lang-pkgs", "Type": "dotnet-core", "Packages": [{"Name": "System.Text.Json", "Version": "10.0.0"}]},
            ],
        }
        write(root / "report.json", report)
        (root / "digest.txt").write_text("sha256:" + "2" * 64 + "\n", encoding="ascii")
        (root / "version.txt").write_text("Version: 0.73.0\n", encoding="ascii")
        invoke(root, True)
        evidence = json.loads((root / "evidence.json").read_text())
        if evidence.get("sourceCommit") != commit or evidence.get("blockingVulnerabilities") != 0:
            raise AssertionError("successful evidence omitted its identity or result")

        report["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2000-0001", "Severity": "HIGH"}]
        write(root / "report.json", report)
        invoke(root, False)
        report["Results"][0].pop("Vulnerabilities")

        report["Results"] = report["Results"][:1]
        write(root / "report.json", report)
        invoke(root, False)

        report["Results"].append({"Target": "app/PkiProxy.Api.deps.json", "Class": "lang-pkgs", "Type": "dotnet-core", "Packages": [{"Name": "System.Text.Json", "Version": "10.0.0"}]})
        report["Metadata"]["ImageID"] = "sha256:" + "3" * 64
        write(root / "report.json", report)
        invoke(root, False)

        print("Runtime image assurance contracts passed: 4.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
