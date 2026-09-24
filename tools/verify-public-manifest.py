#!/usr/bin/env python3
"""Verify every public snapshot file, digest, size and Unix mode."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import unicodedata


class VerificationError(RuntimeError):
    pass


def collision_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def clean_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise VerificationError(f"non-canonical manifest path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise VerificationError(f"manifest path escapes the tree: {value!r}")
    if any(":" in part for part in path.parts):
        raise VerificationError(f"manifest path contains an alternate-stream/path separator: {value!r}")
    return path.as_posix()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(root: Path, manifest_path: Path | None = None) -> dict:
    root = root.resolve()
    manifest_path = (manifest_path or root / "PUBLIC_EXPORT_MANIFEST.json").resolve()
    if not root.is_dir():
        raise VerificationError("public snapshot root is not a directory")
    internal_manifest = root / "PUBLIC_EXPORT_MANIFEST.json"
    if not internal_manifest.is_file() or manifest_path.read_bytes() != internal_manifest.read_bytes():
        raise VerificationError("external and snapshot manifests differ")
    try:
        manifest = json.loads(internal_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid public manifest: {exc}") from exc
    if set(manifest) != {"schemaVersion", "sourceHistoryIncluded", "fileCount", "treeSha256", "files"} or \
            manifest.get("schemaVersion") != 2 or manifest.get("sourceHistoryIncluded") is not False or \
            not isinstance(manifest.get("files"), list):
        raise VerificationError("unsupported or incomplete public manifest")

    entries: list[dict] = []
    paths: set[str] = set()
    collision_keys: dict[str, str] = {}
    for raw in manifest["files"]:
        if not isinstance(raw, dict) or set(raw) != {"path", "sha256", "size", "mode"}:
            raise VerificationError("invalid public manifest file entry")
        relative = clean_relative(raw["path"])
        key = collision_key(relative)
        if relative in paths or key in collision_keys:
            raise VerificationError(f"duplicate/colliding manifest path: {relative}")
        if raw["mode"] not in {"100644", "100755"}:
            raise VerificationError(f"unsupported manifest mode for {relative}")
        if not isinstance(raw["size"], int) or isinstance(raw["size"], bool) or raw["size"] < 0:
            raise VerificationError(f"invalid manifest size for {relative}")
        if not isinstance(raw["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", raw["sha256"]):
            raise VerificationError(f"invalid manifest digest for {relative}")
        paths.add(relative)
        collision_keys[key] = relative
        entries.append(raw)
    if entries != sorted(entries, key=lambda item: item["path"]):
        raise VerificationError("public manifest entries are not canonically ordered")
    if manifest["fileCount"] != len(entries):
        raise VerificationError("public manifest file count mismatch")
    tree_payload = json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if manifest["treeSha256"] != hashlib.sha256(tree_payload).hexdigest():
        raise VerificationError("public manifest tree digest mismatch")

    actual: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise VerificationError(f"link/reparse entry refused: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise VerificationError(f"non-regular entry refused: {relative}")
        actual.add(relative)
    expected = paths | {"PUBLIC_EXPORT_MANIFEST.json"}
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise VerificationError(f"snapshot inventory mismatch; missing={missing}, extra={extra}")

    if os.name != "posix":
        raise VerificationError("authoritative file-mode verification requires POSIX; Linux CI is the release authority")
    for entry in entries:
        path = root.joinpath(*PurePosixPath(entry["path"]).parts)
        metadata = path.lstat()
        expected_mode = 0o755 if entry["mode"] == "100755" else 0o644
        actual_mode = stat.S_IMODE(metadata.st_mode)
        if actual_mode != expected_mode:
            raise VerificationError(
                f"mode mismatch for {entry['path']}: expected {expected_mode:04o}, got {actual_mode:04o}")
        if metadata.st_size != entry["size"] or sha256(path) != entry["sha256"]:
            raise VerificationError(f"content mismatch for {entry['path']}")
    manifest_mode = stat.S_IMODE(internal_manifest.lstat().st_mode)
    if manifest_mode != 0o644:
        raise VerificationError(f"mode mismatch for PUBLIC_EXPORT_MANIFEST.json: expected 0644, got {manifest_mode:04o}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = verify(args.root, args.manifest)
    except (OSError, VerificationError) as exc:
        print(f"public manifest verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"Public manifest verified: {manifest['fileCount']} files with authoritative POSIX modes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
