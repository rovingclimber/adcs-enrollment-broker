#!/usr/bin/env python3
"""Adversarial contracts for the offline Markdown link checker."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


MODULE = Path(__file__).with_name("check-doc-links.py")
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("check_doc_links", MODULE)
assert spec and spec.loader
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def expect_failure(root: Path, text: str) -> None:
    try:
        checker.check(root)
    except checker.LinkError as exc:
        if text not in str(exc):
            raise AssertionError(f"expected {text!r} in {exc!r}") from exc
    else:
        raise AssertionError(f"link checker accepted {text}")


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "docs").mkdir()
        (root / "SECURITY.md").write_text("# Reporting security issues\n", encoding="utf-8")
        index = root / "docs" / "index.md"
        index.write_text("[policy](../SECURITY.md#reporting-security-issues)\n", encoding="utf-8")
        checker.check(root)

        index.write_text("[missing](../SUPPORT.md)\n", encoding="utf-8")
        expect_failure(root, "missing target")
        index.write_text("[fragment](../SECURITY.md#absent)\n", encoding="utf-8")
        expect_failure(root, "missing fragment")
        index.write_text("[escape](../../outside.md)\n", encoding="utf-8")
        expect_failure(root, "link escapes repository")
        index.write_text("`[ignored](../absent.md)`\n\n```md\n[also ignored](../absent.md)\n```\n", encoding="utf-8")
        # Inline code is deliberately unsupported by the small parser, while fenced
        # examples must never be interpreted as links. Keep this contract fenced.
        index.write_text("```md\n[ignored](../absent.md)\n```\n", encoding="utf-8")
        checker.check(root)
    print("Documentation link checker contracts passed: 4.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
