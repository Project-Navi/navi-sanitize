# SPDX-License-Identifier: MIT
"""Tests for the built-site checks in scripts/build_docs.py (no docs build needed)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_docs", ROOT / "scripts" / "build_docs.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bd = _load()

CONFIG = {
    "site_url": "https://docs.example.org/pkg",
    "nav": [{"Home": "index.md"}, {"Ref": [{"API": "reference/api.md"}]}],
}


def _site(tmp_path: Path) -> Path:
    site = tmp_path / "site"
    (site / "reference" / "api").mkdir(parents=True)
    (site / "assets").mkdir()
    (site / "assets" / "logo.png").write_bytes(b"png")
    (site / "index.html").write_text(
        '<a href="reference/api/#clean">api</a><img src="assets/logo.png"><h1 id="top">x</h1>'
    )
    (site / "reference" / "api" / "index.html").write_text(
        '<h2 id="clean">clean</h2><a href="../../">home</a><a href="#clean">self</a>'
        '<a href="/pkg/assets/logo.png">abs</a><a href="https://example.org/">ext</a>'
    )
    (site / "404.html").write_text('<a href="/pkg/">home</a>')
    items = [{"location": ""}, {"location": "reference/api/"}, {"location": "reference/api/#clean"}]
    (site / "search.json").write_text(json.dumps({"config": {}, "items": items}))
    locs = "".join(
        f"<url><loc>https://docs.example.org/pkg/{r}</loc></url>" for r in ("", "reference/api/")
    )
    (site / "sitemap.xml").write_text(f"<urlset>{locs}</urlset>")
    return site


def test_nav_routes() -> None:
    assert bd.nav_routes(CONFIG) == {"", "reference/api/"}


def test_good_site_passes(tmp_path: Path) -> None:
    result = bd.check_site(_site(tmp_path), CONFIG)
    assert result["links_checked"] == 6


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda s: (s / "plans").mkdir() or (s / "plans" / "index.html").write_text(""), "pages"),
        (lambda s: (s / "whitepaper.pdf").write_bytes(b"%PDF"), "non-site file"),
        (lambda s: (s / "index.html").write_text('<a href="missing/">x</a>'), "broken link"),
        (lambda s: (s / "index.html").write_text('<a href="#nowhere">x</a>'), "missing anchor"),
        (lambda s: (s / "404.html").write_text('<a href="/other/">x</a>'), "outside /pkg/"),
        (lambda s: (s / "index.html").write_text('<a href="../../etc">x</a>'), "leaves the site"),
        (
            lambda s: (s / "search.json").write_text(
                json.dumps(
                    {
                        "items": [
                            {"location": ""},
                            {"location": "reference/api/"},
                            {"location": "plans/x/"},
                        ]
                    }
                )
            ),
            "search index has non-nav pages",
        ),
        (lambda s: (s / "sitemap.xml").write_text("<urlset></urlset>"), "sitemap differs"),
    ],
)
def test_bad_site_fails(tmp_path: Path, mutate: object, reason: str) -> None:
    site = _site(tmp_path)
    assert callable(mutate)
    mutate(site)
    with pytest.raises(bd.DocsCheckError, match=reason):
        bd.check_site(site, CONFIG)
