# Contributing to navi-sanitize

This is the canonical maintainer guide: setup, the checks CI runs, conventions and the release path.

## Setup

```bash
git clone https://github.com/Project-Navi/navi-sanitize.git
cd navi-sanitize
uv sync              # dev tools pinned in uv.lock (requires uv)
pre-commit install   # optional; pre-commit is not in the dev group (e.g. uv tool install pre-commit)
```

## Checks

CI runs all of these; `quality-gate` fails unless every one succeeds.

```bash
uv run ruff check src/ tests/ scripts/
uv run ruff format --check src/ tests/ scripts/
uv run mypy --strict src/navi_sanitize/ scripts/
uv run pytest tests/ -v --benchmark-disable          # Python 3.12 and 3.13 in CI

# Docs: builds from a filtered copy of docs/, checks pages, search and links in staging,
# then replaces --out (site/, or a new, empty or previously generated directory outside the checkout)
uv sync --group docs && uv run python scripts/build_docs.py --out site

# Distribution: exact wheel + sdist, installed behavior, sdist rebuild
rm -rf dist && uv build && uv run python scripts/verify_dist.py dist
```

CI also audits the locked dev and docs dependencies with `pip-audit`, and runs Semgrep, OpenSSF Scorecard and Atheris fuzzing:

```bash
uv run --with atheris python fuzz/fuzz_clean.py --target=fuzz_clean -atheris_runs=100000 -max_len=4096
uv run --with atheris python fuzz/fuzz_clean.py --target=fuzz_walk -atheris_runs=100000 -max_len=4096
```

Benchmarks run on demand: `uv run pytest tests/test_benchmark.py -v`. Compare versions on the same machine and interpreter.

CI pins uv (`version:` on each `setup-uv` step) and uses Python 3.12 outside the test matrix, so a new uv release or runner image does not change results mid-run. Dependabot does not bump the uv pin; update it deliberately.

## Conventions

- **Commits:** [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `test:`, `docs:`, `ci:`, `chore:`, `refactor:`, `perf:`).
- **Tests first:** for a bug fix, add a failing regression test, then fix the code. Keep `src/navi_sanitize/` fully covered.
- **Runtime:** standard library only, Python 3.12+, line length 100, `mypy --strict`.
- **Pipeline order is part of the contract.** Null bytes, invisibles, NFKC, homoglyphs, re-NFKC, escaper. See [Pipeline Architecture](https://docs.projectnavi.ai/navi-sanitize/explanation/pipeline-architecture/) before changing a stage, and add attack vectors to `tests/test_adversarial.py` or `tests/test_bypass_attempts.py`.
- **Ported adversarial suite:** `tests/test_adversarial.py` holds cases ported from navi-bootstrap; their expected outputs act as a compatibility oracle, so change them only deliberately.
- **Escaper output is never re-sanitized.** That trust boundary is documented; do not add a second pass.
- **Logs:** messages include counts (`"Stripped 3 invisible character(s)"`) and never input content, keys or values. The library only adds a `NullHandler`.
- **`walk()`** never modifies its input and stays iterative. Tests nested deeper than 128 levels pass `max_depth=` explicitly.
- **Non-Latin test data:** ruff's `RUF001`/`RUF003` fire on intentional Cyrillic, Greek, Armenian or Cherokee characters; such files start with `# ruff: noqa: RUF001, RUF003` (or `RUF003` alone when only comments contain them).
- **Large benchmark payloads** use `benchmark.pedantic()` to bound iterations.

## Pull Requests

1. Branch from `main` (`<type>/<slug>`).
2. Add or update tests with the change.
3. Run the checks above.
4. Keep each PR to one concern and open it against `main`.

## Releases

Maintainers only. Set the version in `pyproject.toml` and `src/navi_sanitize/__init__.py`, run `uv lock`, and add the release to `CHANGELOG.md`. Publishing a GitHub release runs `publish.yml`: CI, the shared build workflow, `verify-dist` on the built artifacts against the release tag, then PyPI Trusted Publishing and release assets. Docs deploy from `main` via `docs.yml`.

## Reporting Bugs

Open an issue on [GitHub Issues](https://github.com/Project-Navi/navi-sanitize/issues) with the Python version, a minimal reproduction, and expected versus actual behavior.

## Security Vulnerabilities

**Do not open a public issue.** See [SECURITY.md](SECURITY.md).
