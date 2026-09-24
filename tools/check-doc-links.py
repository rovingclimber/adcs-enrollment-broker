#!/usr/bin/env python3
"""Check local Markdown links and fragments without network access."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)|!\[[^\]]*\]\(([^)]+)\)")
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
EXPLICIT_ID = re.compile(r"<(?:a\s+(?:name|id)|[^>]+\s+id)=[\"']([^\"']+)[\"']", re.I)
SCHEMES = {"http", "https", "mailto"}


class LinkError(ValueError):
    pass


def markdown_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def github_slug(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value).strip().lower()
    value = re.sub(r"[^\w\- ]", "", value, flags=re.UNICODE)
    return re.sub(r"[ ]+", "-", value)


def fragments(path: Path) -> set[str]:
    found: set[str] = set()
    counts: dict[str, int] = {}
    fenced = False
    for line in markdown_text(path).splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for explicit in EXPLICIT_ID.findall(line):
            found.add(explicit)
        match = HEADING.match(line)
        if match:
            base = github_slug(match.group(2))
            occurrence = counts.get(base, 0)
            counts[base] = occurrence + 1
            found.add(base if occurrence == 0 else f"{base}-{occurrence}")
    return found


def destinations(path: Path) -> list[tuple[int, str]]:
    links: list[tuple[int, str]] = []
    fenced = False
    for number, line in enumerate(markdown_text(path).splitlines(), start=1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for match in LINK.finditer(line):
            raw = (match.group(1) or match.group(2)).strip()
            if raw.startswith("<") and raw.endswith(">"):
                raw = raw[1:-1]
            elif " " in raw:
                raw = raw.split(" ", 1)[0]
            links.append((number, raw))
    return links


def check(root: Path) -> None:
    root = root.resolve()
    failures: list[str] = []
    fragment_cache: dict[Path, set[str]] = {}
    for source in sorted(root.rglob("*.md")):
        if ".git" in source.relative_to(root).parts:
            continue
        for line, raw in destinations(source):
            parsed = urlsplit(raw)
            if parsed.scheme.lower() in SCHEMES or parsed.netloc:
                continue
            relative = unquote(parsed.path)
            target = source if not relative else (source.parent / relative).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                failures.append(f"{source.relative_to(root)}:{line}: link escapes repository: {raw}")
                continue
            if not target.is_file():
                failures.append(f"{source.relative_to(root)}:{line}: missing target: {raw}")
                continue
            if parsed.fragment:
                if target.suffix.lower() != ".md":
                    failures.append(f"{source.relative_to(root)}:{line}: fragment targets non-Markdown file: {raw}")
                    continue
                anchors = fragment_cache.setdefault(target, fragments(target))
                fragment = unquote(parsed.fragment)
                if fragment not in anchors:
                    failures.append(f"{source.relative_to(root)}:{line}: missing fragment: {raw}")
    if failures:
        raise LinkError("\n".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, nargs="?", default=Path("."))
    args = parser.parse_args()
    try:
        check(args.root)
    except (LinkError, OSError, UnicodeError) as exc:
        print(f"documentation link check failed:\n{exc}", file=sys.stderr)
        return 1
    print("Documentation links and fragments passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
