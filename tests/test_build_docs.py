# SPDX-License-Identifier: MIT
"""Tests for scripts/build_docs.py: built-site checks and output-destination safety.

Everything runs in disposable fixtures; only the external zensical build is stubbed.
"""

from __future__ import annotations

import importlib.util
import json
import os
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

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


# --- output destination safety (fixtures only; never the real repository) ---

FIXTURE_SITE_URL = "https://docs.example.org/pkg"
PROTECTED = ("source-sentinel", "docs/index.md", ".git/config", "zensical.toml")


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    (root / "docs").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "source-sentinel").write_text("KEEP")
    (root / "docs" / "index.md").write_text("# KEEP")
    (root / ".git" / "config").write_text("fixture")
    (root / "src" / "pkg" / "__init__.py").write_text("KEEP = 1\n")
    (root / "zensical.toml").write_text(
        f'[project]\nsite_url = "{FIXTURE_SITE_URL}"\nnav = [{{Home = "index.md"}}]\n'
    )
    return root


def _generated_site(path: Path, marker: str = "old") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "index.html").write_text(f"<h1>{marker}</h1>")
    (path / "search.json").write_text(json.dumps({"items": [{"location": ""}]}))
    (path / "sitemap.xml").write_text(f"<urlset><url><loc>{FIXTURE_SITE_URL}/</loc></url></urlset>")
    return path


@pytest.fixture
def builder() -> Iterator[list[Path]]:
    """Stub zensical: writes a minimal site into the staging directory and records calls."""
    calls: list[Path] = []

    def fake_run(*args: Any, **kwargs: Any) -> None:
        stage = Path(kwargs["cwd"])
        calls.append(stage)
        _generated_site(stage / "site", marker="new")

    with patch.object(bd.subprocess, "run", side_effect=fake_run):
        yield calls


def _assert_source_intact(root: Path) -> None:
    for rel in PROTECTED:
        assert (root / rel).is_file(), rel


@pytest.mark.parametrize(
    "target",
    [
        lambda root: root,
        lambda root: root.parent,
        lambda root: root / "docs",
        lambda root: root / ".git",
        lambda root: root / "src",
        lambda root: root / "src" / "pkg" / "new-dir",
        lambda root: root / "docs" / "site",
    ],
    ids=["root", "ancestor", "docs", "git", "src", "new-dir-in-source", "site-under-docs"],
)
def test_refuses_checkout_ancestors_and_source(
    checkout: Path, builder: list[Path], target: Any
) -> None:
    with pytest.raises(bd.DocsCheckError, match="--out"):
        bd.build(checkout, target(checkout))
    assert builder == []  # refused before building or deleting anything
    _assert_source_intact(checkout)


def test_refuses_symlinked_destination(checkout: Path, builder: list[Path]) -> None:
    (checkout / "site").symlink_to(checkout / "docs")
    with pytest.raises(bd.DocsCheckError, match="symlink"):
        bd.build(checkout, checkout / "site")
    assert builder == []
    _assert_source_intact(checkout)


def test_refuses_alias_through_symlinked_parent(
    checkout: Path, builder: list[Path], tmp_path: Path
) -> None:
    alias = tmp_path / "alias"
    alias.symlink_to(checkout)
    for target in (alias, alias / "docs", alias / ".git"):
        with pytest.raises(bd.DocsCheckError, match="--out"):
            bd.build(checkout, target)
    assert builder == []
    _assert_source_intact(checkout)


def test_refuses_existing_unrelated_directory(
    checkout: Path, builder: list[Path], tmp_path: Path
) -> None:
    unrelated = tmp_path / "notes"
    unrelated.mkdir()
    (unrelated / "keep.txt").write_text("KEEP")
    other_repo = tmp_path / "other-repo"
    _generated_site(other_repo)
    (other_repo / ".git").mkdir()
    for target in (unrelated, other_repo):
        with pytest.raises(bd.DocsCheckError, match="not a site generated"):
            bd.build(checkout, target)
    assert (unrelated / "keep.txt").read_text() == "KEEP"
    assert (other_repo / ".git").is_dir()
    assert builder == []


@pytest.mark.parametrize("where", ["checkout-site", "outside-new", "outside-empty"])
def test_builds_into_generated_destinations(
    checkout: Path, builder: list[Path], tmp_path: Path, where: str
) -> None:
    out = {
        "checkout-site": checkout / "site",
        "outside-new": tmp_path / "out" / "site",
        "outside-empty": tmp_path / "empty",
    }[where]
    if where == "outside-empty":
        out.mkdir()
    bd.build(checkout, out)
    assert (out / "index.html").read_text() == "<h1>new</h1>"
    _assert_source_intact(checkout)


@pytest.mark.parametrize("inside", [True, False])
def test_replaces_previous_generated_site(
    checkout: Path, builder: list[Path], tmp_path: Path, inside: bool
) -> None:
    out = _generated_site(checkout / "site" if inside else tmp_path / "published")
    (out / "stale.html").write_text("stale")
    bd.build(checkout, out)
    assert (out / "index.html").read_text() == "<h1>new</h1>"
    assert not (out / "stale.html").exists()
    _assert_source_intact(checkout)


def test_failed_validation_keeps_previous_site(
    checkout: Path, builder: list[Path], tmp_path: Path
) -> None:
    out = _generated_site(tmp_path / "published")

    def reject(site: Path, config: dict[str, object]) -> dict[str, object]:
        raise bd.DocsCheckError("staged site rejected")

    with pytest.raises(bd.DocsCheckError, match="staged site rejected"):
        bd.build(checkout, out, validate=reject)
    assert (out / "index.html").read_text() == "<h1>old</h1>"
    assert len(builder) == 1


def test_cli_refuses_unsafe_out(
    checkout: Path, builder: list[Path], capsys: pytest.CaptureFixture[str]
) -> None:
    cwd = Path.cwd()
    os.chdir(checkout)
    try:
        assert bd.main(["--out", "docs"]) == 1
    finally:
        os.chdir(cwd)
    assert "build_docs: FAIL: --out" in capsys.readouterr().err
    _assert_source_intact(checkout)
