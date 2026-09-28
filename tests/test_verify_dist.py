# SPDX-License-Identifier: MIT
"""Tests for scripts/verify_dist.py: good artifacts pass, bad ones fail for the right reason."""

from __future__ import annotations

import importlib.util
import io
import re
import tarfile
import tomllib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERSION = str(tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"])


def _load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "verify_dist", ROOT / "scripts" / "verify_dist.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vd = _load_verifier()


def _metadata(version: str, extra: str = "") -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        "Name: navi-sanitize\n"
        f"Version: {version}\n"
        "Summary: test fixture\n"
        "Project-URL: Repository, https://github.com/Project-Navi/navi-sanitize\n"
        "Project-URL: Documentation, https://docs.projectnavi.ai/navi-sanitize\n"
        "License-Expression: MIT\n"
        "License-File: LICENSE\n"
        f"Requires-Python: >=3.12\n{extra}\n"
    ).encode()


@dataclass
class Dist:
    """A synthetic wheel + sdist built from the real package sources."""

    version: str = VERSION
    wheel: dict[str, bytes] = field(default_factory=dict)
    sdist: dict[str, bytes] = field(default_factory=dict)
    tamper: dict[str, bytes] = field(default_factory=dict)  # written after RECORD
    wheel_symlinks: tuple[str, ...] = ()
    sdist_symlinks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        info = f"navi_sanitize-{self.version}.dist-info"
        src = ROOT / "src" / "navi_sanitize"
        package = {name: (src / name).read_bytes() for name in vd.PACKAGE_FILES}
        self.wheel = {f"navi_sanitize/{name}": data for name, data in package.items()}
        self.wheel[f"{info}/METADATA"] = _metadata(self.version)
        self.wheel[f"{info}/WHEEL"] = (
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        )
        self.wheel[f"{info}/licenses/LICENSE"] = (ROOT / "LICENSE").read_bytes()
        self.sdist = {f"src/navi_sanitize/{name}": data for name, data in package.items()}
        self.sdist["PKG-INFO"] = _metadata(self.version)
        self.sdist["pyproject.toml"] = f'[project]\nversion = "{self.version}"\n'.encode()
        self.sdist["LICENSE"] = (ROOT / "LICENSE").read_bytes()
        self.sdist["README.md"] = b"# navi-sanitize\n"
        self.sdist["tests/__init__.py"] = b""

    @property
    def info(self) -> str:
        return f"navi_sanitize-{self.version}.dist-info"

    def write(self, dist_dir: Path) -> Path:
        dist_dir.mkdir(parents=True, exist_ok=True)
        rows = [f"{n},{vd._record_digest(d)},{len(d)}" for n, d in self.wheel.items()]
        rows.append(f"{self.info}/RECORD,,")
        with zipfile.ZipFile(
            dist_dir / f"navi_sanitize-{self.version}-py3-none-any.whl", "w"
        ) as zf:
            for name, data in {**self.wheel, **self.tamper}.items():
                zf.writestr(name, data)
            zf.writestr(f"{self.info}/RECORD", "\n".join(rows) + "\n")
            for name in self.wheel_symlinks:
                link = zipfile.ZipInfo(name)
                link.external_attr = 0o120777 << 16
                zf.writestr(link, "target")
        root = f"navi_sanitize-{self.version}"
        with tarfile.open(dist_dir / f"{root}.tar.gz", "w:gz") as tf:
            for name, data in self.sdist.items():
                member = tarfile.TarInfo(f"{root}/{name}")
                member.size = len(data)
                tf.addfile(member, io.BytesIO(data))
            for name in self.sdist_symlinks:
                member = tarfile.TarInfo(f"{root}/{name}")
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                tf.addfile(member)
        return dist_dir


def _fails(dist: Dist, tmp_path: Path, reason: str) -> None:
    with pytest.raises(vd.VerificationError, match=reason):
        vd.inspect_artifacts(dist.write(tmp_path / "dist"), dist.version)


def test_good_artifacts_pass_static_checks(tmp_path: Path) -> None:
    wheel, sdist, files = vd.inspect_artifacts(Dist().write(tmp_path / "dist"), VERSION)
    assert wheel.name.endswith(".whl") and sdist.name.endswith(".tar.gz")
    assert f"navi_sanitize-{VERSION}.dist-info/METADATA" in files


class TestVersionReconciliation:
    def test_tag_must_match_pyproject(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nversion = "1.2.3"\n')
        assert vd.expected_version(pyproject, "v1.2.3") == "1.2.3"
        assert vd.expected_version(pyproject, None) == "1.2.3"
        with pytest.raises(vd.VerificationError, match=re.escape("!= version 1.2.3")):
            vd.expected_version(pyproject, "v1.2.4")

    @pytest.mark.parametrize("tag", ["1.2.3", "v1.2", "v1.2.3rc1", "v1.2.3; echo x", "v1.2.3\n"])
    def test_malformed_tag_rejected(self, tmp_path: Path, tag: str) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nversion = "1.2.3"\n')
        with pytest.raises(vd.VerificationError, match="not of the form"):
            vd.expected_version(pyproject, tag)

    def test_metadata_version_mismatch(self, tmp_path: Path) -> None:
        dist = Dist()
        dist.wheel[f"{dist.info}/METADATA"] = _metadata("0.0.1")
        _fails(dist, tmp_path, "Version is '0.0.1'")

    def test_artifacts_for_another_version(self, tmp_path: Path) -> None:
        dist_dir = Dist(version="0.0.1").write(tmp_path / "dist")
        with pytest.raises(vd.VerificationError, match="expected navi_sanitize-"):
            vd.inspect_artifacts(dist_dir, VERSION)


class TestWheelContents:
    def test_missing_typing_marker(self, tmp_path: Path) -> None:
        dist = Dist()
        del dist.wheel["navi_sanitize/py.typed"]
        _fails(dist, tmp_path, "wheel members differ")

    def test_unexpected_pth_file(self, tmp_path: Path) -> None:
        dist = Dist()
        dist.wheel["evil.pth"] = b"import os\n"
        _fails(dist, tmp_path, "wheel members differ")

    def test_unsafe_member_name(self, tmp_path: Path) -> None:
        dist = Dist()
        dist.wheel["../escape.py"] = b""
        _fails(dist, tmp_path, "unsafe archive member")

    def test_symlink_member(self, tmp_path: Path) -> None:
        _fails(Dist(wheel_symlinks=("navi_sanitize/link.py",)), tmp_path, "non-regular member")

    def test_record_digest_mismatch(self, tmp_path: Path) -> None:
        dist = Dist(tamper={"navi_sanitize/escapers/_path.py": b"# replaced\n"})
        _fails(dist, tmp_path, "RECORD mismatch: navi_sanitize/escapers/_path.py")

    def test_runtime_dependency(self, tmp_path: Path) -> None:
        dist = Dist()
        dist.wheel[f"{dist.info}/METADATA"] = _metadata(VERSION, "Requires-Dist: six\n")
        _fails(dist, tmp_path, "Requires-Dist")

    def test_license_missing(self, tmp_path: Path) -> None:
        dist = Dist()
        del dist.wheel[f"{dist.info}/licenses/LICENSE"]
        _fails(dist, tmp_path, "wheel members differ")


class TestSdistContents:
    @pytest.mark.parametrize("name", ["CLAUDE.md", ".github/workflows/ci.yml", "tests/x.pyc"])
    def test_forbidden_member(self, tmp_path: Path, name: str) -> None:
        dist = Dist()
        dist.sdist[name] = b"x"
        _fails(dist, tmp_path, "forbidden sdist member")

    def test_unexpected_top_level_member(self, tmp_path: Path) -> None:
        dist = Dist()
        dist.sdist[".cache/123"] = b"x"
        _fails(dist, tmp_path, "unexpected sdist member")

    def test_symlink_member(self, tmp_path: Path) -> None:
        _fails(Dist(sdist_symlinks=("docs/link",)), tmp_path, "non-regular sdist member")

    def test_missing_license(self, tmp_path: Path) -> None:
        dist = Dist()
        del dist.sdist["LICENSE"]
        _fails(dist, tmp_path, "sdist missing")

    def test_wheel_and_sdist_sources_differ(self, tmp_path: Path) -> None:
        dist = Dist()
        dist.sdist["src/navi_sanitize/escapers/_path.py"] = b"# different\n"
        _fails(dist, tmp_path, "wheel/sdist differ: escapers/_path.py")


class TestInstalledSmoke:
    """The real install path: a fresh venv, --no-index --no-deps, smoke run with -I."""

    def test_good_wheel_passes(self, tmp_path: Path) -> None:
        wheel, _, _ = vd.inspect_artifacts(Dist().write(tmp_path / "dist"), VERSION)
        result = vd.install_and_smoke(wheel, tmp_path, VERSION)
        assert result["module"].startswith(str(tmp_path))

    def test_missing_export_fails(self, tmp_path: Path) -> None:
        dist = Dist()
        init = dist.wheel["navi_sanitize/__init__.py"].decode()
        dist.wheel["navi_sanitize/__init__.py"] = init.replace('    "walk",\n', "").encode()
        wheel = dist.write(tmp_path / "dist") / f"navi_sanitize-{VERSION}-py3-none-any.whl"
        with pytest.raises(vd.VerificationError, match="__all__ is"):
            vd.install_and_smoke(wheel, tmp_path, VERSION)

    def test_behavior_regression_fails(self, tmp_path: Path) -> None:
        dist = Dist()
        path_src = dist.wheel["navi_sanitize/escapers/_path.py"].decode()
        dist.wheel["navi_sanitize/escapers/_path.py"] = path_src.replace(
            'stripped and stripped != "."', "stripped"
        ).encode()
        wheel = dist.write(tmp_path / "dist") / f"navi_sanitize-{VERSION}-py3-none-any.whl"
        with pytest.raises(vd.VerificationError, match="path escaper dot segment"):
            vd.install_and_smoke(wheel, tmp_path, VERSION)


def test_cli_reports_failure_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dist_dir = Dist().write(tmp_path / "dist")
    assert (
        vd.main([str(dist_dir), "--tag", "v0.0.0", "--pyproject", str(ROOT / "pyproject.toml")])
        == 1
    )
    assert "verify_dist: FAIL: tag 'v0.0.0'" in capsys.readouterr().err
