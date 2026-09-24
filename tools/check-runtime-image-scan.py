#!/usr/bin/env python3
"""Validate and bind a Trivy report to one exact release-image archive."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile


class ScanError(RuntimeError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def load_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanError(f"invalid JSON document {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ScanError(f"JSON document is not an object: {path}")
    return value


def valid_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def provenance_identity(provenance: dict) -> tuple[str, dict[str, str]]:
    if provenance.get("kind") == "pkiproxy-ci-build-provenance":
        commit = provenance.get("source", {}).get("commit")
        outputs = provenance.get("outputs", {})
        expected = {
            "artifact-sha256": outputs.get("artifact", {}).get("sha256"),
            "sbom-sha256": outputs.get("sbom", {}).get("sha256"),
        }
    else:
        commit = provenance.get("commit")
        expected = {}
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", commit) is None:
        raise ScanError("provenance has no valid source commit")
    if any(not valid_sha(item) for item in expected.values()):
        raise ScanError("provenance output identity is incomplete")
    return commit, expected


def image_configuration(archive: Path) -> tuple[str, dict]:
    try:
        with tarfile.open(archive, "r:*") as image:
            manifest_member = image.getmember("manifest.json")
            manifest_file = image.extractfile(manifest_member)
            if manifest_file is None:
                raise ScanError("image archive manifest is unreadable")
            manifests = json.load(manifest_file)
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise ScanError("image archive must contain exactly one manifest")
            config_name = manifests[0].get("Config")
            if not isinstance(config_name, str) or Path(config_name).name != config_name:
                raise ScanError("image archive config path is unsafe")
            config_file = image.extractfile(image.getmember(config_name))
            if config_file is None:
                raise ScanError("image archive config is unreadable")
            config_bytes = config_file.read()
            config = json.loads(config_bytes)
    except (KeyError, tarfile.TarError, json.JSONDecodeError, OSError) as exc:
        raise ScanError(f"invalid release-image archive: {exc}") from exc
    if not isinstance(config, dict):
        raise ScanError("image configuration is not an object")
    return hashlib.sha256(config_bytes).hexdigest(), config


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--image-archive", type=Path, required=True)
    parser.add_argument("--image-digest", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--scanner-version", type=Path, required=True)
    parser.add_argument("--scanner-reference", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = load_object(args.report)
        provenance = load_object(args.provenance)
        commit, expected_outputs = provenance_identity(provenance)
        if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
            raise ScanError("Trivy report has the wrong schema or artifact type")
        results = report.get("Results")
        if not isinstance(results, list) or not results:
            raise ScanError("Trivy report contains no scan results")
        classes = {item.get("Class") for item in results if isinstance(item, dict)}
        if not {"os-pkgs", "lang-pkgs"}.issubset(classes):
            raise ScanError("Trivy did not inventory both OS and application packages")
        if not any(isinstance(item.get("Packages"), list) and item["Packages"] for item in results if isinstance(item, dict)):
            raise ScanError("Trivy report contains no package inventory")
        forbidden = []
        for result in results:
            if not isinstance(result, dict):
                raise ScanError("Trivy result entry is malformed")
            for vulnerability in result.get("Vulnerabilities") or []:
                if vulnerability.get("Severity") in {"HIGH", "CRITICAL"}:
                    forbidden.append(vulnerability.get("VulnerabilityID", "unknown"))
        if forbidden:
            raise ScanError("release image contains blocking vulnerabilities: " + ", ".join(sorted(set(forbidden))))

        image_digest = args.image_digest.read_text(encoding="ascii").strip()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is None:
            raise ScanError("builder did not emit a valid image manifest digest")
        config_digest, config = image_configuration(args.image_archive)
        metadata_image = report.get("Metadata", {}).get("ImageID", "")
        if metadata_image not in {config_digest, "sha256:" + config_digest}:
            raise ScanError("Trivy report image identity does not match the scanned archive")
        labels = config.get("config", {}).get("Labels") or config.get("Config", {}).get("Labels") or {}
        if labels.get("org.opencontainers.image.revision") != commit:
            raise ScanError("image source label does not match provenance")
        provenance_hash = digest(args.provenance)
        provenance_labels = [value for key, value in labels.items() if key.endswith(".provenance-sha256")]
        if provenance_labels != [provenance_hash]:
            raise ScanError("image provenance label does not match provenance bytes")
        for suffix, expected in expected_outputs.items():
            values = [value for key, value in labels.items() if key.endswith("." + suffix)]
            if values != [expected]:
                raise ScanError(f"image {suffix} label does not match provenance")
        scanner_version = args.scanner_version.read_text(encoding="utf-8").splitlines()
        if not scanner_version or re.fullmatch(r"Version:\s+0\.73\.0", scanner_version[0]) is None:
            raise ScanError("unexpected Trivy scanner version")
        if "@sha256:" not in args.scanner_reference:
            raise ScanError("scanner image reference is not digest pinned")

        evidence = {
            "schemaVersion": 1,
            "kind": "pki-proxy-runtime-image-assurance",
            "sourceCommit": commit,
            "provenanceSha256": provenance_hash,
            "image": {
                "manifestDigest": image_digest,
                "configDigest": "sha256:" + config_digest,
                "archiveSha256": digest(args.image_archive),
            },
            "scanner": {"reference": args.scanner_reference, "version": "0.73.0"},
            "policy": {"severities": ["HIGH", "CRITICAL"], "osPackages": True, "applicationPackages": True},
            "reportSha256": digest(args.report),
            "blockingVulnerabilities": 0,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print("Runtime image scan is complete, identity-bound, and policy-clean")
        return 0
    except (ScanError, OSError, ValueError) as exc:
        print(f"runtime image assurance failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
