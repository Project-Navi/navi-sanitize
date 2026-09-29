#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify built navi-sanitize distributions before they are published.

Checks the exact wheel and sdist in DIST_DIR: safe archive members, the
expected file set, metadata, version/tag agreement, installed behavior of
every public export in a fresh virtual environment outside the checkout,
and a wheel rebuilt from the sdist alone. Prints SHA-256 digests.

Usage (from the repository root, so pyproject.toml supplies the version):
  python scripts/verify_dist.py DIST_DIR [--tag vX.Y.Z] [--report FILE]

Stdlib only; `uv` must be on PATH to rebuild the sdist. Never uploads.
"""

from __future__ import annotations

import argparse
import base64
import csv
import email.parser
import hashlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

DIST_NAME = "navi-sanitize"
PKG = "navi_sanitize"
PACKAGE_FILES = frozenset(
    {
        "__init__.py",
        "_decode.py",
        "_homoglyphs.py",
        "_invisible.py",
        "_pipeline.py",
        "_scripts.py",
        "py.typed",
        "escapers/__init__.py",
        "escapers/_jinja2.py",
        "escapers/_path.py",
    }
)
EXPORTS = frozenset(
    {
        "Escaper",
        "clean",
        "decode_evasion",
        "detect_scripts",
        "is_mixed_script",
        "jinja2_escaper",
        "path_escaper",
        "walk",
    }
)
TAG_RE = re.compile(r"v(\d+\.\d+\.\d+)")
SDIST_REQUIRED = frozenset(
    {"PKG-INFO", "pyproject.toml", "LICENSE", "README.md", "tests/__init__.py"}
)
SDIST_TOP_LEVEL = SDIST_REQUIRED - {"tests/__init__.py"} | {
    ".gitignore",  # always added by hatchling
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "SECURITY.md",
    "docs",
    "examples",
    "fuzz",
    "scripts",
    "src",
    "tests",
    "uv.lock",
    "zensical.toml",
}
SDIST_FORBIDDEN = re.compile(
    r"(^|/)(CLAUDE\.md|\.github|\.env[^/]*|__pycache__|\.venv|site|dist|docs/plans|docs/whitepaper)"
    r"(/|$)|\.(pyc|pyo|pth|so|pem|key)$"
)


class VerificationError(Exception):
    """A distribution failed verification."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_version(pyproject: Path, tag: str | None) -> str:
    """Reconcile pyproject.toml's version with the release tag, if any."""
    version = str(tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"])
    if tag is not None:
        match = TAG_RE.fullmatch(tag)
        check(match is not None, f"tag {tag!r} is not of the form vX.Y.Z")
        check(match is not None and match.group(1) == version, f"tag {tag!r} != version {version}")
    return version


def find_artifacts(dist_dir: Path, version: str) -> tuple[Path, Path]:
    wheel = dist_dir / f"{PKG}-{version}-py3-none-any.whl"
    sdist = dist_dir / f"{PKG}-{version}.tar.gz"
    found = sorted(p.name for p in dist_dir.iterdir() if p.name != ".gitignore")  # uv writes one
    check(
        found == sorted([wheel.name, sdist.name]),
        f"expected {wheel.name} and {sdist.name}, found {found}",
    )
    return wheel, sdist


def check_member_name(name: str) -> None:
    path = PurePosixPath(name)
    check(
        bool(name)
        and not path.is_absolute()
        and "\\" not in name
        and ":" not in path.parts[0]
        and all(part not in ("", ".", "..") for part in path.parts),
        f"unsafe archive member name {name!r}",
    )


def check_metadata(text: str, version: str) -> None:
    msg = email.parser.Parser().parsestr(text)
    check(msg["Name"] == DIST_NAME, f"Name is {msg['Name']!r}")
    check(msg["Version"] == version, f"Version is {msg['Version']!r}, expected {version}")
    check(msg["Requires-Python"] == ">=3.12", f"Requires-Python is {msg['Requires-Python']!r}")
    check(not msg.get_all("Requires-Dist"), "runtime Requires-Dist declared")
    check(
        msg["License-Expression"] == "MIT", f"License-Expression is {msg['License-Expression']!r}"
    )
    check("LICENSE" in (msg.get_all("License-File") or []), "License-File LICENSE missing")
    check(bool(msg["Summary"]), "Summary missing")
    urls = dict(u.split(", ", 1) for u in msg.get_all("Project-URL") or [])
    check(
        urls.get("Documentation") == "https://docs.projectnavi.ai/navi-sanitize",
        f"Documentation URL is {urls.get('Documentation')!r}",
    )
    check("Repository" in urls, "Repository URL missing")


def _record_digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def read_wheel(path: Path, version: str) -> dict[str, bytes]:
    """Inspect a wheel and return its members' contents."""
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        names = [i.filename for i in infos]
        check(len(names) == len(set(names)), "duplicate wheel members")
        for info in infos:
            check_member_name(info.filename)
            file_type = (info.external_attr >> 16) & 0o170000  # 0 means unspecified
            check(file_type in (0, 0o100000), f"non-regular member {info.filename}")
        check(zf.testzip() is None, "corrupt wheel member")
        files = {i.filename: zf.read(i) for i in infos}
    info_dir = f"{PKG}-{version}.dist-info"
    expected = {f"{PKG}/{f}" for f in PACKAGE_FILES} | {
        f"{info_dir}/{f}" for f in ("METADATA", "WHEEL", "RECORD", "licenses/LICENSE")
    }
    check(set(files) == expected, f"wheel members differ: {sorted(set(files) ^ expected)}")
    rows = [row for row in csv.reader(io.StringIO(files[f"{info_dir}/RECORD"].decode())) if row]
    record = {row[0]: row[1:] for row in rows}
    check(len(record) == len(rows), "duplicate RECORD rows")
    check(set(record) == expected, "RECORD does not list exactly the wheel members")
    for name, data in files.items():
        if name != f"{info_dir}/RECORD":
            check(
                record[name] == [_record_digest(data), str(len(data))], f"RECORD mismatch: {name}"
            )
    wheel = email.parser.Parser().parsestr(files[f"{info_dir}/WHEEL"].decode())
    check(wheel["Root-Is-Purelib"] == "true", "wheel is not purelib")
    check(wheel.get_all("Tag") == ["py3-none-any"], f"wheel tags {wheel.get_all('Tag')}")
    check_metadata(files[f"{info_dir}/METADATA"].decode(), version)
    check(files[f"{info_dir}/licenses/LICENSE"].startswith(b"MIT License"), "LICENSE is not MIT")
    return files


def read_sdist(path: Path, version: str) -> dict[str, bytes]:
    """Inspect an sdist and return its regular files, keyed relative to its root."""
    root = f"{PKG}-{version}"
    files: dict[str, bytes] = {}
    with tarfile.open(path, "r:gz") as tf:
        for member in tf.getmembers():
            check_member_name(member.name)
            check(member.isfile() or member.isdir(), f"non-regular sdist member {member.name}")
            check(PurePosixPath(member.name).parts[0] == root, f"member outside {root}/")
            rel = member.name.removeprefix(root).lstrip("/")
            if member.isfile():
                check(rel not in files, f"duplicate sdist member {rel}")
                check(not SDIST_FORBIDDEN.search(rel), f"forbidden sdist member {rel}")
                check(rel.split("/")[0] in SDIST_TOP_LEVEL, f"unexpected sdist member {rel}")
                extracted = tf.extractfile(member)
                check(extracted is not None, f"unreadable sdist member {rel}")
                files[rel] = extracted.read() if extracted else b""
    src_files = {k for k in files if k.startswith("src/")}
    expected_src = {f"src/{PKG}/{name}" for name in PACKAGE_FILES}
    check(src_files == expected_src, f"sdist src/ files differ: {sorted(src_files ^ expected_src)}")
    missing = SDIST_REQUIRED - set(files)
    check(not missing, f"sdist missing {sorted(missing)}")
    check_metadata(files["PKG-INFO"].decode(), version)
    pyproject = tomllib.loads(files["pyproject.toml"].decode())
    check(pyproject["project"]["version"] == version, "sdist pyproject.toml version mismatch")
    check(files["LICENSE"].startswith(b"MIT License"), "sdist LICENSE is not MIT")
    return files


def check_sdist_matches_source(sdist: dict[str, bytes], source_root: Path) -> None:
    """Every sdist file except the generated PKG-INFO must equal the checked-out source."""
    for rel, data in sorted(sdist.items()):
        if rel == "PKG-INFO":
            continue
        source = source_root / rel
        check(source.is_file(), f"sdist file not in the checked-out source: {rel}")
        check(source.read_bytes() == data, f"sdist file differs from the checked-out source: {rel}")


def check_same_package(wheel: dict[str, bytes], sdist: dict[str, bytes]) -> None:
    for name in PACKAGE_FILES:
        check(wheel[f"{PKG}/{name}"] == sdist[f"src/{PKG}/{name}"], f"wheel/sdist differ: {name}")


def check_same_wheel(direct: dict[str, bytes], rebuilt: dict[str, bytes]) -> None:
    """Rebuilt wheel must match except the generator stamp (WHEEL) and its RECORD row."""
    for name in sorted(set(direct) | set(rebuilt)):
        if name.endswith((".dist-info/WHEEL", ".dist-info/RECORD")):
            continue
        check(direct.get(name) == rebuilt.get(name), f"sdist-rebuilt wheel differs: {name}")


def _clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "VIRTUAL_ENV"))}
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def _run(cmd: list[str], cwd: Path) -> str:
    proc = subprocess.run(cmd, cwd=cwd, env=_clean_env(), capture_output=True, text=True)
    check(proc.returncode == 0, f"{cmd[:3]} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout


def install_and_smoke(wheel: Path, workdir: Path, version: str) -> dict[str, str]:
    """Install the wheel alone into a fresh venv and run the smoke checks there."""
    venv = workdir / "venv"
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    uv = shutil.which("uv")
    if uv:  # works even where the interpreter lacks ensurepip (e.g. Debian system Python)
        _run([sys.executable, "-m", "venv", "--without-pip", str(venv)], workdir)
        install = [uv, "pip", "install", "--python", str(python), "--quiet"]
    else:
        _run([sys.executable, "-m", "venv", str(venv)], workdir)
        install = [str(python), "-m", "pip", "install", "-q"]
    _run([*install, "--no-index", "--no-deps", str(wheel)], workdir)
    out = _run([str(python), "-I", str(Path(__file__).resolve()), "--smoke", version], workdir)
    result: dict[str, str] = json.loads(out)
    return result


def rebuild_from_sdist(sdist: Path, workdir: Path, version: str) -> Path:
    """Extract the sdist safely and build a wheel from it with no checkout access."""
    with tarfile.open(sdist, "r:gz") as tf:
        tf.extractall(workdir / "extracted", filter="data")
    out = workdir / "rebuilt"
    source = workdir / "extracted" / f"{PKG}-{version}"
    _run(
        ["uv", "build", "--wheel", "--python", sys.executable, "--out-dir", str(out), str(source)],
        workdir,
    )
    wheels = list(out.glob("*.whl"))
    check(len(wheels) == 1, f"expected one rebuilt wheel, found {wheels}")
    return wheels[0]


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _raises_type_error(fn: Callable[[], object]) -> bool:
    try:
        fn()
    except TypeError:
        return True
    return False


def smoke(version: str) -> dict[str, str]:
    """Exercise every public export of the installed package. Runs inside the venv."""
    import importlib.metadata
    import inspect

    import navi_sanitize as ns

    pkg_dir = Path(ns.__file__).resolve().parent
    purelib = Path(sysconfig.get_paths()["purelib"]).resolve()
    check(pkg_dir.parent == purelib, f"imported from {pkg_dir}, not {purelib}")
    check((pkg_dir / "py.typed").is_file(), "installed py.typed missing")
    check(set(ns.__all__) == EXPORTS, f"__all__ is {sorted(ns.__all__)}")
    check(all(hasattr(ns, name) for name in EXPORTS), "an export is missing")
    check(ns.__version__ == version, f"__version__ is {ns.__version__}")
    check(importlib.metadata.version(DIST_NAME) == version, "installed metadata version mismatch")
    check(not importlib.metadata.requires(DIST_NAME), "runtime dependency declared")
    check(inspect.signature(ns.walk).parameters["max_depth"].default == 128, "walk default")
    check(
        inspect.signature(ns.decode_evasion).parameters["max_layers"].default == 3, "decode default"
    )

    capture = _Capture()
    logging.getLogger(PKG).addHandler(capture)
    logging.getLogger(PKG).setLevel(logging.DEBUG)
    records = capture.records

    secret = "SMOKE_SENTINEL"
    check(ns.clean("n\u0430vi\x00\u200b" + secret) == "navi" + secret, "clean pipeline")
    check(ns.clean("\uff21\uff22\uff23") == "ABC", "clean NFKC")
    check(ns.clean("{{%", escaper=ns.jinja2_escaper) == "\\{\\{\\%", "jinja2 escaper")
    check(ns.path_escaper(".../file") == "file", "path escaper dot segment")
    check(ns.clean("../../etc/passwd", escaper=ns.path_escaper) == "etc/passwd", "path escaper")
    check(ns.decode_evasion("%252e%252e%252fetc%252fpasswd") == "../etc/passwd", "decode")
    check(ns.decode_evasion("\ud800%41") == "\ud800A", "decode surrogate")
    check(ns.detect_scripts("a\u0430") == {"latin", "cyrillic"}, "detect_scripts")
    check(ns.is_mixed_script("a\u0430") and not ns.is_mixed_script("abc"), "is_mixed_script")
    escaper: ns.Escaper = str.upper
    check(ns.clean("ok", escaper=escaper) == "OK", "Escaper alias")
    data: dict[str, object] = {"k\u200b": ["v\x00"], secret: 1, secret + "\u200b": 2}
    data["self"] = data
    out = ns.walk(data)
    check(out["k"] == ["v"] and out["self"] is out and out[secret] == 2, "walk")
    check(data["k\u200b"] == ["v\x00"], "walk mutated its input")
    check(any("collision" in r.getMessage() for r in records), "collision warning")
    check(_raises_type_error(lambda: ns.clean(42)), "clean(non-str) did not raise")  # type: ignore[arg-type]
    check(
        _raises_type_error(lambda: ns.clean("x", escaper=lambda _: 1)),  # type: ignore[arg-type, return-value]
        "non-str escaper output did not raise",
    )
    check(all(secret not in r.getMessage() + repr(r.args) for r in records), "input logged")
    return {"module": str(pkg_dir), "python": sys.version.split()[0]}


def inspect_artifacts(
    dist_dir: Path, version: str, source_root: Path | None = None
) -> tuple[Path, Path, dict[str, bytes]]:
    """Static checks of both archives; returns (wheel, sdist, wheel contents).

    With *source_root*, the sdist must also match that checkout file for file.
    """
    wheel, sdist = find_artifacts(dist_dir, version)
    wheel_files = read_wheel(wheel, version)
    sdist_files = read_sdist(sdist, version)
    check_same_package(wheel_files, sdist_files)
    if source_root is not None:
        check_sdist_matches_source(sdist_files, source_root)
    return wheel, sdist, wheel_files


def verify(dist_dir: Path, tag: str | None, pyproject: Path) -> dict[str, object]:
    version = expected_version(pyproject, tag)
    wheel, sdist, wheel_files = inspect_artifacts(dist_dir, version, pyproject.resolve().parent)
    with tempfile.TemporaryDirectory(prefix="verify-dist-") as tmp:
        work = Path(tmp)
        (work / "direct").mkdir()
        (work / "rebuild").mkdir()
        direct_smoke = install_and_smoke(wheel, work / "direct", version)
        rebuilt = rebuild_from_sdist(sdist, work / "rebuild", version)
        check_same_wheel(wheel_files, read_wheel(rebuilt, version))
        rebuilt_smoke = install_and_smoke(rebuilt, work / "rebuild", version)
        rebuilt_digest = sha256(rebuilt)
    return {
        "version": version,
        "tag": tag,
        "sha256": {wheel.name: sha256(wheel), sdist.name: sha256(sdist)},
        "sdist_rebuilt_wheel_sha256": rebuilt_digest,
        "installed_wheel": direct_smoke,
        "installed_sdist_rebuilt_wheel": rebuilt_smoke,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("dist_dir", nargs="?", type=Path)
    parser.add_argument("--tag", help="release tag that must match the version, e.g. v0.2.2")
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--report", type=Path, help="write the JSON result here")
    parser.add_argument("--smoke", metavar="VERSION", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.smoke:
            print(json.dumps(smoke(args.smoke)))
            return 0
        if args.dist_dir is None:
            parser.error("dist_dir is required")
        result = verify(args.dist_dir, args.tag, args.pyproject)
    except VerificationError as exc:
        print(f"verify_dist: FAIL: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2)
    if args.report:
        args.report.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
