#!/usr/bin/env python3
"""Validate and bind a Trivy report to one exact release-image archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from typing import BinaryIO


class ScanError(RuntimeError):
    pass


APP_DIRECTORY = PurePosixPath("app")
API_DLL = APP_DIRECTORY / "PkiProxy.Api.dll"
PACKAGE_CLASSES = {"os-pkgs", "lang-pkgs"}


def stream_digest(stream: BinaryIO) -> str:
    value = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        value.update(chunk)
    return value.hexdigest()


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return stream_digest(stream)


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


def provenance_identity(provenance: dict) -> tuple[str, dict[str, str], str | None]:
    api_digest = None
    if provenance.get("kind") == "pkiproxy-ci-build-provenance":
        commit = provenance.get("source", {}).get("commit")
        outputs = provenance.get("outputs", {})
        expected = {
            "artifact-sha256": outputs.get("artifact", {}).get("sha256"),
            "sbom-sha256": outputs.get("sbom", {}).get("sha256"),
        }
        dlls = outputs.get("principalDlls")
        api_digest = dlls.get(API_DLL.name) if isinstance(dlls, dict) else None
        if not valid_sha(api_digest):
            raise ScanError("provenance has no valid broker API DLL digest")
    else:
        commit = provenance.get("commit")
        expected = {}
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", commit) is None:
        raise ScanError("provenance has no valid source commit")
    if any(not valid_sha(item) for item in expected.values()):
        raise ScanError("provenance output identity is incomplete")
    return commit, expected, api_digest


def safe_archive_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or "\0" in name:
        raise ScanError("unsafe path in image archive")
    return path


def image_members(image: tarfile.TarFile) -> dict[PurePosixPath, tarfile.TarInfo]:
    members: dict[PurePosixPath, tarfile.TarInfo] = {}
    for member in image:
        name = safe_archive_path(member.name)
        if not (member.isfile() or member.isdir()):
            raise ScanError("image archive contains a non-file entry")
        if name in members:
            raise ScanError("duplicate path in image archive")
        members[name] = member
    return members


def open_image_file(image: tarfile.TarFile, member: tarfile.TarInfo) -> BinaryIO:
    if not member.isfile():
        raise ScanError("image archive metadata and layers must be regular files")
    stream = image.extractfile(member)
    if stream is None:
        raise ScanError("image archive file is unreadable")
    return stream


def layer_diff_id(image: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    with open_image_file(image, member) as stream:
        compressed = stream.read(2) == b"\x1f\x8b"
        stream.seek(0)
        if compressed:
            with gzip.GzipFile(fileobj=stream) as layer:
                return "sha256:" + stream_digest(layer)
        return "sha256:" + stream_digest(stream)


def read_layer(image: tarfile.TarFile, member: tarfile.TarInfo):
    entries: dict[PurePosixPath, tarfile.TarInfo] = {}
    removed: set[PurePosixPath] = set()
    opaque: set[PurePosixPath] = set()
    seen: set[PurePosixPath] = set()
    api_digest = None
    with open_image_file(image, member) as stream, tarfile.open(fileobj=stream, mode="r|*") as layer:
        for entry in layer:
            if entry.isdir() and entry.name in {"", "."}:
                continue  # Kaniko emits an empty-name directory for the root.
            path = safe_archive_path(entry.name)
            if not path.parts:
                raise ScanError("invalid image layer root entry")
            if path in seen:
                raise ScanError("duplicate path in image layer")
            seen.add(path)
            if path.name.startswith(".wh."):
                if not entry.isfile() or entry.size != 0 or path.name == ".wh.":
                    raise ScanError("invalid image layer whiteout")
                if path.name == ".wh..wh..opq":
                    opaque.add(path.parent)
                else:
                    target = path.name[4:]
                    if target in {".", ".."}:
                        raise ScanError("unsafe image layer whiteout target")
                    removed.add(path.parent / target)
                continue
            entries[path] = entry
            if path == API_DLL and entry.isfile():
                with open_image_file(layer, entry) as payload:
                    api_digest = stream_digest(payload)
    return entries, removed, opaque, api_digest


def effective_api_digest(image: tarfile.TarFile, members: dict[PurePosixPath, tarfile.TarInfo],
                         layers: object, config: dict) -> str | None:
    if not isinstance(layers, list) or not layers or any(not isinstance(name, str) for name in layers):
        raise ScanError("image archive has no valid layers")
    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
        raise ScanError("image configuration has no layered root filesystem")
    diff_ids = rootfs.get("diff_ids")
    if not isinstance(diff_ids, list) or len(diff_ids) != len(layers):
        raise ScanError("image configuration layer digest count does not match the archive")
    symlinks: set[PurePosixPath] = set()
    api_digest = None
    app_is_nondirectory = False
    for name, diff_id in zip(layers, diff_ids):
        member = members[safe_archive_path(name)]
        if layer_diff_id(image, member) != diff_id:
            raise ScanError("image archive layer digest does not match the configuration")
        entries, removed, opaque, layer_api_digest = read_layer(image, member)
        # Whiteouts apply to lower layers only, regardless of their order in this layer.
        layer_symlinks = {path for path, entry in entries.items() if entry.issym()}
        for path in removed | opaque:
            if (any(parent in symlinks or parent in layer_symlinks for parent in path.parents)
                    or (path in opaque and (path in symlinks or path in layer_symlinks))):
                raise ScanError("image layer whiteout traverses a symlink")
        symlinks = {path for path in symlinks if not (
            any(path.is_relative_to(parent) for parent in removed) or any(parent in opaque for parent in path.parents)
        )}
        if any(API_DLL.is_relative_to(parent) for parent in removed) or any(parent in opaque for parent in API_DLL.parents):
            api_digest = None
        if any(APP_DIRECTORY.is_relative_to(parent) for parent in removed) or any(parent in opaque for parent in APP_DIRECTORY.parents):
            app_is_nondirectory = False
        for path, entry in entries.items():
            if any(parent in symlinks for parent in path.parents):
                raise ScanError("image layer path traverses a symlink")
            if entry.issym():
                symlinks.add(path)
            else:
                symlinks.discard(path)
            if path == APP_DIRECTORY:
                app_is_nondirectory = not entry.isdir()
                if app_is_nondirectory:
                    api_digest = None
            elif path == API_DLL:
                if app_is_nondirectory:
                    raise ScanError("broker API DLL does not have a regular parent directory")
                api_digest = layer_api_digest
            elif API_DLL in path.parents:
                if API_DLL in entries and not entries[API_DLL].isdir():
                    raise ScanError("conflicting broker API DLL paths in image layer")
                api_digest = None
    return api_digest


def image_configuration(archive: Path, expected_api_digest: str | None) -> tuple[str, dict]:
    try:
        with tarfile.open(archive, "r:*") as image:
            members = image_members(image)
            with open_image_file(image, members[PurePosixPath("manifest.json")]) as manifest_file:
                manifests = json.load(manifest_file)
            if not isinstance(manifests, list) or len(manifests) != 1 or not isinstance(manifests[0], dict):
                raise ScanError("image archive must contain exactly one manifest")
            config_name = manifests[0].get("Config")
            if not isinstance(config_name, str):
                raise ScanError("image archive config path is unsafe")
            with open_image_file(image, members[safe_archive_path(config_name)]) as config_file:
                config_bytes = config_file.read()
            config = json.loads(config_bytes)
            if not isinstance(config, dict):
                raise ScanError("image configuration is not an object")
            if expected_api_digest is not None:
                actual_api_digest = effective_api_digest(image, members, manifests[0].get("Layers"), config)
                if actual_api_digest != expected_api_digest:
                    raise ScanError("image broker API DLL digest does not match provenance")
    except (KeyError, EOFError, tarfile.TarError, json.JSONDecodeError, OSError) as exc:
        raise ScanError(f"invalid release-image archive: {exc}") from exc
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
        commit, expected_outputs, expected_api_digest = provenance_identity(provenance)
        if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
            raise ScanError("Trivy report has the wrong schema or artifact type")
        results = report.get("Results")
        if not isinstance(results, list) or not results:
            raise ScanError("Trivy report contains no scan results")
        forbidden = []
        inventoried = set()
        for result in results:
            if not isinstance(result, dict):
                raise ScanError("Trivy result entry is malformed")
            package_class = result.get("Class")
            packages = result.get("Packages")
            if isinstance(package_class, str) and isinstance(packages, list) and any(
                    isinstance(package, dict) and isinstance(package.get("Name"), str) and package["Name"]
                    for package in packages):
                inventoried.add(package_class)
            for vulnerability in result.get("Vulnerabilities") or []:
                if vulnerability.get("Severity") in {"HIGH", "CRITICAL"}:
                    forbidden.append(vulnerability.get("VulnerabilityID", "unknown"))
        if not PACKAGE_CLASSES.issubset(inventoried):
            raise ScanError("Trivy did not inventory both OS and application packages")
        if forbidden:
            raise ScanError("release image contains blocking vulnerabilities: " + ", ".join(sorted(set(forbidden))))

        image_digest = args.image_digest.read_text(encoding="ascii").strip()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is None:
            raise ScanError("builder did not emit a valid image manifest digest")
        config_digest, config = image_configuration(args.image_archive, expected_api_digest)
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
        if not scanner_version or re.fullmatch(r"Version:\s+0\.76\.2", scanner_version[0]) is None:
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
            "scanner": {"reference": args.scanner_reference, "version": "0.76.2"},
            "policy": {"severities": ["HIGH", "CRITICAL"], "osPackages": True, "applicationPackages": True},
            "reportSha256": digest(args.report),
            "blockingVulnerabilities": 0,
        }
        if expected_api_digest is not None:
            evidence["image"]["apiDllSha256"] = expected_api_digest
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print("Runtime image scan is complete, identity-bound, and policy-clean")
        return 0
    except (ScanError, OSError, ValueError) as exc:
        print(f"runtime image assurance failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
