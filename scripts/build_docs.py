#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the documentation site from a filtered copy of docs/ and check it.

Internal material (docs/plans, docs/internal) and the whitepaper sources are
left out *before* generation, so they cannot reach pages, the search index
or the sitemap. The built site must contain exactly the pages in the
zensical.toml nav (plus 404.html), and every relative link, fragment and
asset must resolve inside the site.

Usage (from the repository root, with the docs dependency group installed):
  python scripts/build_docs.py [--out site]

Nothing is deployed. The checkout is not modified except for --out.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

EXCLUDED_SOURCES = ("plans", "internal", "whitepaper")
FORBIDDEN_SUFFIXES = (".md", ".tex", ".pdf", ".gitkeep", ".gitignore", ".py")


class DocsCheckError(Exception):
    """The built site failed a check."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise DocsCheckError(message)


def nav_routes(config: dict[str, object]) -> set[str]:
    """Routes ('' for the home page, 'a/b/' otherwise) of every nav entry."""
    routes: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
        elif isinstance(node, dict):
            for value in node.values():
                visit(value)
        elif isinstance(node, str):
            check(node.endswith(".md"), f"unexpected nav entry {node!r}")
            stem = node.removesuffix(".md")
            routes.add("" if stem == "index" else stem.removesuffix("/index") + "/")

    visit(config["nav"])
    return routes


def build(root: Path, out: Path) -> dict[str, object]:
    """Build from a filtered copy of docs/ and move the result to *out*."""
    config: dict[str, object] = tomllib.loads((root / "zensical.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    with tempfile.TemporaryDirectory(prefix="docs-build-") as tmp:
        stage = Path(tmp)
        shutil.copy2(root / "zensical.toml", stage / "zensical.toml")
        docs = root / "docs"
        shutil.copytree(
            docs,
            stage / "docs",
            ignore=lambda d, names: [n for n in names if Path(d) == docs and n in EXCLUDED_SOURCES],
        )
        subprocess.run(
            [sys.executable, "-m", "zensical", "build"], cwd=stage, check=True, stdout=sys.stderr
        )
        if out.exists():
            shutil.rmtree(out)
        shutil.move(stage / "site", out)
    return config


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if value is None:
                continue
            if name in ("id", "name"):
                self.ids.add(value)
            elif name in ("href", "src"):
                self.links.append(value)


def _target_file(site: Path, page_url: str, link_path: str) -> Path:
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(page_url), link_path))
    check(not resolved.startswith(".."), f"{page_url}: link {link_path!r} leaves the site")
    target = site / resolved
    return target / "index.html" if target.is_dir() else target


def check_site(site: Path, config: dict[str, object]) -> dict[str, object]:
    routes = nav_routes(config)
    base = urlsplit(str(config["site_url"])).path.rstrip("/") + "/"
    pages = {p.relative_to(site).as_posix() for p in site.rglob("*.html")}
    expected = {f"{r}index.html" for r in routes} | {"404.html"}
    check(pages == expected, f"built pages differ from nav: {sorted(pages ^ expected)}")
    for item in site.rglob("*"):
        rel = item.relative_to(site).as_posix()
        check(not rel.endswith(FORBIDDEN_SUFFIXES), f"non-site file in output: {rel}")
        check(rel.split("/")[0] not in EXCLUDED_SOURCES, f"excluded material in output: {rel}")

    search = json.loads((site / "search.json").read_text(encoding="utf-8"))
    locations = {item["location"].split("#")[0] for item in search["items"]}
    check(locations <= routes, f"search index has non-nav pages: {sorted(locations - routes)}")
    check(locations == routes, f"search index misses pages: {sorted(routes - locations)}")
    sitemap = re.findall(r"<loc>([^<]*)</loc>", (site / "sitemap.xml").read_text(encoding="utf-8"))
    site_url = str(config["site_url"]).rstrip("/") + "/"
    check(sorted(sitemap) == sorted(site_url + r for r in routes), f"sitemap differs: {sitemap}")

    parsed: dict[str, _Page] = {}
    for rel in sorted(pages):
        parser = _Page()
        parser.feed((site / rel).read_text(encoding="utf-8"))
        parsed[rel] = parser
    links = 0
    for rel, page in parsed.items():
        for link in page.links:
            parts = urlsplit(link)
            if parts.scheme or parts.netloc or link.startswith("mailto:"):
                continue
            path = parts.path
            if path.startswith("/"):
                check(path.startswith(base), f"{rel}: {link!r} is outside {base}")
                path = posixpath.relpath(path, posixpath.dirname(base + rel))
            target = _target_file(site, rel, path) if path else site / rel
            check(target.is_file(), f"{rel}: broken link {link!r}")
            if parts.fragment and target.suffix == ".html":
                target_rel = target.relative_to(site).as_posix()
                check(parts.fragment in parsed[target_rel].ids, f"{rel}: missing anchor {link!r}")
            links += 1
    return {"pages": sorted(pages), "search_locations": sorted(locations), "links_checked": links}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=Path("site"))
    args = parser.parse_args(argv)
    try:
        config = build(Path.cwd(), args.out)
        result = check_site(args.out, config)
    except DocsCheckError as exc:
        print(f"build_docs: FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
