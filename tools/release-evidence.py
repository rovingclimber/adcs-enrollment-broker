#!/usr/bin/env python3
"""Create and verify public release-candidate evidence using local files only."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Iterable


class EvidenceError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def checked_relative(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise EvidenceError(f"non-canonical path: {value!r}")
    return path.as_posix()


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(["git", *arguments], cwd=root, text=True, capture_output=True, check=False)
    if result.returncode:
        raise EvidenceError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def tracked_inventory(root: Path) -> list[dict]:
    paths = [checked_relative(item) for item in git(root, "ls-files").splitlines() if item]
    entries: list[dict] = []
    for relative in sorted(paths):
        path = root.joinpath(*PurePosixPath(relative).parts)
        if path.is_symlink() or not path.is_file():
            raise EvidenceError(f"tracked path is not a regular file: {relative}")
        entries.append({"path": relative, "sha256": digest(path), "size": path.stat().st_size})
    return entries


def directory_inventory(root: Path) -> list[dict]:
    if not root.is_dir():
        raise EvidenceError(f"artifact directory is missing: {root}")
    entries: list[dict] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise EvidenceError(f"artifact contains a symbolic link: {path.relative_to(root)}")
        if path.is_file():
            relative = checked_relative(path.relative_to(root).as_posix())
            entries.append({"path": relative, "sha256": digest(path), "size": path.stat().st_size})
    return entries


def reject_build_environment_metadata(build: Path) -> None:
    markers = {"/builds/"}
    for name in ("CI_PROJECT_DIR", "CI_PROJECT_PATH", "CI_SERVER_HOST"):
        value = os.environ.get(name)
        if value:
            markers.add(value)
            markers.add(value.replace("\\", "/"))
    encoded = [value.casefold().encode("utf-8") for value in markers if value]
    for path in sorted(build.rglob("*")):
        if not path.is_file():
            continue
        lowered = path.read_bytes().lower()
        if any(marker in lowered for marker in encoded):
            raise EvidenceError("build artifact contains CI host, project, or runner path metadata")


def verify_manifest(root: Path) -> None:
    path = root / "PUBLIC_EXPORT_MANIFEST.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read public manifest: {exc}") from exc
    if manifest.get("schemaVersion") != 2 or manifest.get("sourceHistoryIncluded") is not False:
        raise EvidenceError("unsupported or unsafe public manifest")
    forbidden = {"sourceCommit", "sourcePath", "sourceSha256", "transformations"}
    if forbidden.intersection(manifest):
        raise EvidenceError("public manifest contains private provenance fields")
    files = manifest.get("files")
    if not isinstance(files, list) or manifest.get("fileCount") != len(files):
        raise EvidenceError("public manifest count mismatch")
    expected: dict[str, dict] = {}
    for item in files:
        if set(item) != {"path", "sha256", "size", "mode"}:
            raise EvidenceError("public manifest file entry has unexpected fields")
        relative = checked_relative(str(item["path"]))
        if relative in expected:
            raise EvidenceError(f"duplicate public manifest path: {relative}")
        expected[relative] = item
    if not {"LICENSE", "NOTICE"}.issubset(expected):
        raise EvidenceError("public manifest omits LICENSE or NOTICE")
    actual_paths = set(git(root, "ls-files").splitlines())
    if actual_paths != set(expected) | {"PUBLIC_EXPORT_MANIFEST.json"}:
        raise EvidenceError("tracked inventory differs from public manifest")
    for relative, item in expected.items():
        file_path = root.joinpath(*PurePosixPath(relative).parts)
        if digest(file_path) != item["sha256"] or file_path.stat().st_size != item["size"]:
            raise EvidenceError(f"public manifest mismatch: {relative}")
    tree_payload = json.dumps(files, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(tree_payload).hexdigest() != manifest.get("treeSha256"):
        raise EvidenceError("public manifest tree hash mismatch")


def package_rows(root: Path) -> list[dict[str, str]]:
    packages: dict[tuple[str, str], dict[str, str]] = {}
    for lock_path in sorted(root.rglob("packages.lock.json")):
        data = json.loads(lock_path.read_text(encoding="utf-8"))
        dependencies = data.get("dependencies", {})
        for framework in dependencies.values():
            if not isinstance(framework, dict):
                continue
            for name, details in framework.items():
                if not isinstance(details, dict):
                    continue
                version = details.get("resolved")
                content_hash = details.get("contentHash")
                if not isinstance(version, str) or not isinstance(content_hash, str):
                    continue
                key = (name.casefold(), version)
                row = {"name": name, "version": version, "contentHash": content_hash}
                if key in packages and packages[key] != row:
                    raise EvidenceError(f"conflicting locked package metadata: {name} {version}")
                packages[key] = row
    return [packages[key] for key in sorted(packages)]


def package_license(package: dict[str, str], cache: Path) -> tuple[str, str]:
    name = package["name"]
    version = package["version"]
    package_dir = cache / name.casefold() / version
    nuspecs = sorted(package_dir.glob("*.nuspec"))
    if len(nuspecs) != 1:
        raise EvidenceError(f"expected one restored nuspec for {name} {version}")
    root = ET.parse(nuspecs[0]).getroot()
    licenses = [element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "license"]
    if len(licenses) != 1 or licenses[0].attrib.get("type") != "expression":
        raise EvidenceError(f"package has no unambiguous SPDX license expression: {name} {version}")
    expression = (licenses[0].text or "").strip()
    if not expression or not re.fullmatch(r"[A-Za-z0-9.+()\- ]+(?:\s(?:AND|OR|WITH)\s[A-Za-z0-9.+()\- ]+)*", expression):
        raise EvidenceError(f"package has an invalid SPDX license expression: {name} {version}")
    try:
        sha512 = base64.b64decode(package["contentHash"], validate=True).hex()
    except ValueError as exc:
        raise EvidenceError(f"package has an invalid locked content hash: {name} {version}") from exc
    if len(sha512) != 128:
        raise EvidenceError(f"package has an invalid locked content hash: {name} {version}")
    return expression, sha512


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def create(root: Path, build: Path, output: Path) -> None:
    verify_manifest(root)
    reject_build_environment_metadata(build)
    if output.exists() and any(output.iterdir()):
        raise EvidenceError("evidence output must be empty")
    output.mkdir(parents=True, exist_ok=True)
    source_files = tracked_inventory(root)
    build_files = directory_inventory(build)
    inventory = {"schemaVersion": 1, "files": source_files}
    write_json(output / "release-inventory.json", inventory)

    packages = []
    relationships = []
    package_cache = Path(os.environ.get("NUGET_PACKAGES", Path.home() / ".nuget" / "packages"))
    for index, package in enumerate(package_rows(root), start=1):
        name = package["name"]
        version = package["version"]
        declared_license, sha512 = package_license(package, package_cache)
        identifier = f"SPDXRef-Package-{index}"
        packages.append({
            "SPDXID": identifier,
            "name": name,
            "versionInfo": version,
            "downloadLocation": f"https://api.nuget.org/v3-flatcontainer/{name.casefold()}/{version}/{name.casefold()}.{version}.nupkg",
            "filesAnalyzed": False,
            "licenseConcluded": declared_license,
            "licenseDeclared": declared_license,
            "checksums": [{"algorithm": "SHA512", "checksumValue": sha512}],
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:nuget/{name}@{version}",
            }],
        })
        relationships.append({
            "spdxElementId": "SPDXRef-Application",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": identifier,
        })
    namespace_seed = hashlib.sha256(canonical(source_files)).hexdigest()
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "pki-enrollment-broker",
        "documentNamespace": f"https://example.test/spdx/pki-enrollment-broker/{namespace_seed}",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: release-evidence.py"]},
        "packages": [{
            "SPDXID": "SPDXRef-Application",
            "name": "pki-enrollment-broker",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
        }, *packages],
        "relationships": relationships,
    }
    write_json(output / "application.spdx.json", sbom)
    provenance = {
        "schemaVersion": 1,
        "commit": git(root, "rev-parse", "HEAD"),
        "tree": git(root, "rev-parse", "HEAD^{tree}"),
        "ref": os.environ.get("CI_COMMIT_REF_NAME", "local-clean-room"),
        "pipelineId": os.environ.get("CI_PIPELINE_ID", "local"),
        "jobId": os.environ.get("CI_JOB_ID", "local"),
        "protectedRef": os.environ.get("CI_COMMIT_REF_PROTECTED", "false").lower() == "true",
        "publicManifestSha256": digest(root / "PUBLIC_EXPORT_MANIFEST.json"),
        "sourceInventorySha256": hashlib.sha256(canonical(inventory)).hexdigest(),
        "licenseSha256": digest(root / "LICENSE"),
        "noticeSha256": digest(root / "NOTICE"),
        "buildFiles": build_files,
        "unsigned": True,
    }
    write_json(output / "provenance.json", provenance)


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read JSON document {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"JSON document must be an object: {path}")
    return value


def valid_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def verify_ci(root: Path, manifest_path: Path, build: Path, allow_unprotected: bool = False) -> dict:
    verify_manifest(root)
    value = load_json(manifest_path)
    if value.get("schemaVersion") != 1 or value.get("unsigned") is not True:
        raise EvidenceError("unsupported CI provenance")
    if not allow_unprotected and value.get("protectedRef") is not True:
        raise EvidenceError("release artifact did not originate from a protected ref")
    commit = value.get("commit")
    tree = value.get("tree")
    if not valid_digest(commit) and not (isinstance(commit, str) and len(commit) == 40 and all(c in "0123456789abcdef" for c in commit)):
        raise EvidenceError("invalid source commit")
    if not (isinstance(tree, str) and len(tree) in {40, 64} and all(c in "0123456789abcdef" for c in tree)):
        raise EvidenceError("invalid source tree")
    if git(root, "rev-parse", "HEAD") != commit or git(root, "rev-parse", "HEAD^{tree}") != tree:
        raise EvidenceError("checked-out source does not match CI provenance")
    if digest(root / "PUBLIC_EXPORT_MANIFEST.json") != value.get("publicManifestSha256"):
        raise EvidenceError("public export manifest does not match CI provenance")
    inventory = {"schemaVersion": 1, "files": tracked_inventory(root)}
    if hashlib.sha256(canonical(inventory)).hexdigest() != value.get("sourceInventorySha256"):
        raise EvidenceError("source inventory does not match CI provenance")
    if digest(root / "LICENSE") != value.get("licenseSha256"):
        raise EvidenceError("LICENSE does not match CI provenance")
    if digest(root / "NOTICE") != value.get("noticeSha256"):
        raise EvidenceError("NOTICE does not match CI provenance")
    expected = value.get("buildFiles")
    if not isinstance(expected, list) or expected != directory_inventory(build):
        raise EvidenceError("application artifact does not match CI provenance")
    if not any(item.get("path") == "PkiProxy.Api.dll" for item in expected if isinstance(item, dict)):
        raise EvidenceError("application artifact has no broker entry assembly")
    return value


def field(manifest_path: Path, name: str) -> None:
    value: object = load_json(manifest_path)
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            raise EvidenceError(f"unknown manifest field: {name}")
        value = value[part]
    if not isinstance(value, (str, int, bool)):
        raise EvidenceError(f"manifest field is not scalar: {name}")
    print(str(value).lower() if isinstance(value, bool) else value)


def image_identity(inspect_path: Path, api_digest_path: Path) -> dict:
    raw = json.loads(inspect_path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or len(raw) != 1:
        raise EvidenceError("image inspection must describe exactly one image")
    item = raw[0]
    image_id = item.get("Id", "")
    user = item.get("Config", {}).get("User", "")
    labels = item.get("Config", {}).get("Labels") or {}
    api_digest = api_digest_path.read_text(encoding="ascii").strip().split()[0]
    if not image_id.startswith("sha256:") or not valid_digest(image_id[7:]):
        raise EvidenceError("invalid image identity")
    if user in {"", "0", "0:0", "root", "root:root"}:
        raise EvidenceError("release image runs as root")
    if not valid_digest(api_digest):
        raise EvidenceError("invalid runtime application digest")
    return {
        "imageId": image_id,
        "runtimeUser": user,
        "labels": labels,
        "apiDllSha256": api_digest,
        "architecture": item.get("Architecture"),
        "os": item.get("Os"),
    }


def finalize_image(manifest_path: Path, inspect_path: Path, api_digest_path: Path,
                   runtime_packages: Path, application_sbom: Path, generation: str, output: Path) -> None:
    ci = load_json(manifest_path)
    image = image_identity(inspect_path, api_digest_path)
    expected_dll = next((item.get("sha256") for item in ci.get("buildFiles", [])
                         if isinstance(item, dict) and item.get("path") == "PkiProxy.Api.dll"), None)
    expected_labels = {
        "org.opencontainers.image.revision": ci.get("commit"),
        "org.example.pki-proxy.pipeline-id": str(ci.get("pipelineId")),
        "org.example.pki-proxy.job-id": str(ci.get("jobId")),
        "org.example.pki-proxy.provenance-sha256": digest(manifest_path),
    }
    if any(image["labels"].get(key) != value for key, value in expected_labels.items()):
        raise EvidenceError("runtime labels do not match CI provenance")
    if image["apiDllSha256"] != expected_dll:
        raise EvidenceError("runtime application does not match CI artifact")
    result = {
        "schemaVersion": 1,
        "kind": "pki-proxy-release-provenance",
        "unsigned": True,
        "ciProvenanceSha256": digest(manifest_path),
        "source": {"commit": ci.get("commit"), "tree": ci.get("tree"), "protectedRef": ci.get("protectedRef")},
        "builder": {"pipelineId": ci.get("pipelineId"), "jobId": ci.get("jobId")},
        "image": {**image, "generation": generation},
        "runtimePackageInventorySha256": digest(runtime_packages),
        "applicationSbomSha256": digest(application_sbom),
        "admission": {"protectedRefRequired": True, "hashChainVerified": True, "deployed": False},
    }
    write_json(output, result)


def verify_image(manifest_path: Path, inspect_path: Path, api_digest_path: Path) -> None:
    release = load_json(manifest_path)
    if release.get("kind") != "pki-proxy-release-provenance" or release.get("unsigned") is not True:
        raise EvidenceError("unsupported release provenance")
    if release.get("source", {}).get("protectedRef") is not True or release.get("admission", {}).get("hashChainVerified") is not True:
        raise EvidenceError("release provenance is not protected and admitted")
    evidence_dir = manifest_path.parent
    if digest(evidence_dir / "ci-provenance.json") != release.get("ciProvenanceSha256"):
        raise EvidenceError("CI provenance hash chain is broken")
    if digest(evidence_dir / "application.spdx.json") != release.get("applicationSbomSha256"):
        raise EvidenceError("application SBOM hash chain is broken")
    if digest(evidence_dir / "dpkg-status") != release.get("runtimePackageInventorySha256"):
        raise EvidenceError("runtime package inventory hash chain is broken")
    actual = image_identity(inspect_path, api_digest_path)
    expected = release.get("image", {})
    for key in ("imageId", "runtimeUser", "labels", "apiDllSha256", "architecture", "os"):
        if actual.get(key) != expected.get(key):
            raise EvidenceError(f"runtime image mismatch: {key}")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-manifest")
    verify.add_argument("--root", type=Path, required=True)
    generate = subparsers.add_parser("create")
    generate.add_argument("--root", type=Path, required=True)
    generate.add_argument("--build", type=Path, required=True)
    generate.add_argument("--output", type=Path, required=True)
    verify_ci_parser = subparsers.add_parser("verify-ci")
    verify_ci_parser.add_argument("--root", type=Path, required=True)
    verify_ci_parser.add_argument("--manifest", type=Path, required=True)
    verify_ci_parser.add_argument("--build", type=Path, required=True)
    verify_ci_parser.add_argument("--allow-unprotected", action="store_true")
    field_parser = subparsers.add_parser("field")
    field_parser.add_argument("--manifest", type=Path, required=True)
    field_parser.add_argument("--name", required=True)
    finalize_parser = subparsers.add_parser("finalize-image")
    finalize_parser.add_argument("--manifest", type=Path, required=True)
    finalize_parser.add_argument("--inspect", type=Path, required=True)
    finalize_parser.add_argument("--api-digest", type=Path, required=True)
    finalize_parser.add_argument("--runtime-packages", type=Path, required=True)
    finalize_parser.add_argument("--application-sbom", type=Path, required=True)
    finalize_parser.add_argument("--generation", required=True)
    finalize_parser.add_argument("--output", type=Path, required=True)
    verify_image_parser = subparsers.add_parser("verify-image")
    verify_image_parser.add_argument("--manifest", type=Path, required=True)
    verify_image_parser.add_argument("--inspect", type=Path, required=True)
    verify_image_parser.add_argument("--api-digest", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify-manifest":
            verify_manifest(args.root.resolve())
        elif args.command == "create":
            create(args.root.resolve(), args.build.resolve(), args.output.resolve())
        elif args.command == "verify-ci":
            verify_ci(args.root.resolve(), args.manifest.resolve(), args.build.resolve(), args.allow_unprotected)
        elif args.command == "field":
            field(args.manifest.resolve(), args.name)
        elif args.command == "finalize-image":
            finalize_image(args.manifest.resolve(), args.inspect.resolve(), args.api_digest.resolve(),
                           args.runtime_packages.resolve(), args.application_sbom.resolve(),
                           args.generation, args.output.resolve())
        elif args.command == "verify-image":
            verify_image(args.manifest.resolve(), args.inspect.resolve(), args.api_digest.resolve())
    except (EvidenceError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"release evidence failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
