#!/usr/bin/env python3
"""Focused package-license contracts for release evidence."""

from __future__ import annotations

import base64
import importlib.util
import sys
import tempfile
from pathlib import Path


MODULE = Path(__file__).with_name("release-evidence.py")
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("release_evidence", MODULE)
assert spec and spec.loader
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


def expect_failure(package: dict[str, str], cache: Path, text: str) -> None:
    try:
        evidence.package_license(package, cache)
    except evidence.EvidenceError as exc:
        if text not in str(exc):
            raise AssertionError(f"expected {text!r} in {exc!r}") from exc
    else:
        raise AssertionError(f"package license accepted: {text}")


def main() -> int:
    package = {
        "name": "Example.Package",
        "version": "1.2.3",
        "contentHash": base64.b64encode(bytes(range(64))).decode("ascii"),
    }
    with tempfile.TemporaryDirectory() as temporary:
        cache = Path(temporary)
        package_dir = cache / "example.package" / "1.2.3"
        package_dir.mkdir(parents=True)
        nuspec = package_dir / "example.package.nuspec"
        nuspec.write_text("<package><metadata><license type='expression'>MIT</license></metadata></package>", encoding="utf-8")
        assert evidence.package_license(package, cache) == ("MIT", bytes(range(64)).hex())

        nuspec.write_text("<package><metadata><license type='file'>LICENSE</license></metadata></package>", encoding="utf-8")
        expect_failure(package, cache, "no unambiguous SPDX")
        nuspec.write_text("<package><metadata /></package>", encoding="utf-8")
        expect_failure(package, cache, "no unambiguous SPDX")
        package["contentHash"] = "not-base64"
        nuspec.write_text("<package><metadata><license type='expression'>MIT</license></metadata></package>", encoding="utf-8")
        expect_failure(package, cache, "invalid locked content hash")
    print("Release-evidence package-license contracts passed: 4.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
