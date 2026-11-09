#!/usr/bin/env python3
"""Adversarial contracts for the runtime image assurance evidence gate."""

from __future__ import annotations

import hashlib
import gzip
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


def invoke(root: Path, expected: bool, diagnostic: str = "") -> None:
    result = subprocess.run([
        sys.executable, str(TOOL), "--report", str(root / "report.json"),
        "--image-archive", str(root / "image.tar"), "--image-digest", str(root / "digest.txt"),
        "--provenance", str(root / "provenance.json"), "--scanner-version", str(root / "version.txt"),
        "--scanner-reference", "scanner.invalid/trivy@sha256:" + "7" * 64,
        "--output", str(root / "evidence.json"),
    ], text=True, capture_output=True, check=False)
    if result.returncode != (0 if expected else 1) or diagnostic not in result.stdout:
        raise AssertionError(f"unexpected result {result.returncode}: {result.stdout}\n{result.stderr}")


def add_file(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mtime = 0
    archive.addfile(member, io.BytesIO(content))


def make_layer(entries: dict[str, bytes | tarfile.TarInfo], *, compressed: bool = True) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as layer:
        for name, content in entries.items():
            if isinstance(content, tarfile.TarInfo):
                layer.addfile(content)
            else:
                add_file(layer, name, content)
    payload = buffer.getvalue()
    return gzip.compress(payload, mtime=0) if compressed else payload


def make_archive(path: Path, config: dict, layers: tuple[bytes, ...] = (), *, unsafe_layer: bool = False) -> str:
    config_bytes = canonical(config)
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    layer_names = [f"layer-{i}.tar" for i, _ in enumerate(layers)]
    manifest_layers = ["../" + layer_names[0], *layer_names[1:]] if unsafe_layer else layer_names
    manifest = canonical([{"Config": config_digest + ".json", "RepoTags": ["fixture:scan"], "Layers": manifest_layers}])
    with tarfile.open(path, "w") as archive:
        for name, content in (("manifest.json", manifest), (config_digest + ".json", config_bytes)):
            add_file(archive, name, content)
        for name, content in zip(layer_names, layers):
            add_file(archive, name, content)
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
        (root / "version.txt").write_text("Version: 0.76.2\n", encoding="ascii")
        invoke(root, True)
        evidence = json.loads((root / "evidence.json").read_text())
        if evidence.get("sourceCommit") != commit or evidence.get("blockingVulnerabilities") != 0:
            raise AssertionError("successful evidence omitted its identity or result")

        report["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2000-0001", "Severity": "HIGH"}]
        write(root / "report.json", report)
        invoke(root, False)
        report["Results"][0].pop("Vulnerabilities")

        application_inventory = report["Results"].pop()
        write(root / "report.json", report)
        invoke(root, False, "both OS and application packages")

        report["Results"].append({**application_inventory, "Packages": []})
        write(root / "report.json", report)
        invoke(root, False, "both OS and application packages")

        report["Results"][-1] = application_inventory
        report["Metadata"]["ImageID"] = "sha256:" + "3" * 64
        write(root / "report.json", report)
        invoke(root, False, "image identity does not match")

        api_bytes = b"verified broker API fixture"
        api_digest = hashlib.sha256(api_bytes).hexdigest()
        provenance = {
            "schemaVersion": 1, "kind": "pkiproxy-ci-build-provenance", "source": {"commit": commit},
            "outputs": {"artifact": {"sha256": "4" * 64}, "sbom": {"sha256": "5" * 64},
                        "principalDlls": {"PkiProxy.Api.dll": api_digest}},
        }
        write(root / "provenance.json", provenance)
        config["config"]["Labels"].update({
            "org.example.pki-proxy.provenance-sha256": hashlib.sha256((root / "provenance.json").read_bytes()).hexdigest(),
            "org.example.pki-proxy.artifact-sha256": "4" * 64,
            "org.example.pki-proxy.sbom-sha256": "5" * 64,
        })
        dll = "app/PkiProxy.Api.dll"
        root_directory = tarfile.TarInfo("")
        root_directory.type = tarfile.DIRTYPE
        good = make_layer({"": root_directory, "./" + dll: api_bytes})
        swapped = make_layer({dll: b"different broker API fixture"})
        link = tarfile.TarInfo("app")
        link.type = tarfile.SYMTYPE
        link.linkname = "elsewhere"
        alias = tarfile.TarInfo("alias")
        alias.type = tarfile.SYMTYPE
        alias.linkname = "app"

        def image_case(layers: tuple[bytes, ...], expected: bool, diagnostic: str = "", *,
                       unsafe_layer: bool = False, configured_layers: tuple[bytes, ...] | None = None) -> None:
            config["rootfs"] = {
                "type": "layers",
                "diff_ids": ["sha256:" + hashlib.sha256(gzip.decompress(data) if data.startswith(b"\x1f\x8b") else data).hexdigest()
                             for data in (configured_layers if configured_layers is not None else layers)],
            }
            config_digest = make_archive(root / "image.tar", config, layers, unsafe_layer=unsafe_layer)
            report["Metadata"]["ImageID"] = "sha256:" + config_digest
            write(root / "report.json", report)
            invoke(root, expected, diagnostic)

        image_case((good,), True)
        if json.loads((root / "evidence.json").read_text())["image"].get("apiDllSha256") != api_digest:
            raise AssertionError("private evidence omitted the verified API DLL digest")

        image_case((swapped,), False, "DLL digest does not match provenance")
        image_case((swapped,), False, "layer digest does not match the configuration", configured_layers=(good,))
        image_case((good, swapped), False, "DLL digest does not match provenance")
        image_case((good, make_layer({"app/.wh.PkiProxy.Api.dll": b""})), False, "DLL digest does not match provenance")
        image_case((good, make_layer({"app/.wh..wh..opq": b""})), False, "DLL digest does not match provenance")
        image_case((good, make_layer({".wh.app": b""})), False, "DLL digest does not match provenance")
        image_case((good, make_layer({"app": link})), False, "DLL digest does not match provenance")
        image_case((good, make_layer({"alias": alias}), make_layer({"alias/PkiProxy.Api.dll": b"different"})),
                   False, "path traverses a symlink")
        image_case((swapped, make_layer({dll: api_bytes, "app/.wh..wh..opq": b""}, compressed=False)), True)
        image_case((good,), False, "unsafe path", unsafe_layer=True)

        del provenance["outputs"]["principalDlls"]
        write(root / "provenance.json", provenance)
        invoke(root, False, "no valid broker API DLL digest")

        print("Runtime image assurance contracts passed: 17.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
