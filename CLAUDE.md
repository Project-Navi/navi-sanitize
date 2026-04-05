# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

navi-sanitize is a standalone, zero-dependency Python library extracted from navi-bootstrap. It provides deterministic input sanitization for untrusted text — no ML, legitimate Unicode preserved by design. Python 3.12+, stdlib only.

## Commands

```bash
# Install dev dependencies
uv sync

# Run tests (disable benchmarks for speed)
uv run pytest tests/ -v --benchmark-disable

# Run a single test file
uv run pytest tests/test_clean.py -v --benchmark-disable

# Run a single test
uv run pytest tests/test_clean.py::test_name -v --benchmark-disable

# Run benchmarks
uv run pytest tests/test_benchmark.py -v

# Lint and format
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/

# Type check
uv run mypy src/navi_sanitize/

# Build wheel
uv build

# Pre-commit setup (one-time)
pre-commit install

# Run all pre-commit hooks
pre-commit run --all-files
```

## CI

GitHub Actions runs on push to `main` and all PRs. Four parallel required checks, then downstream gates:

- **lint** — `ruff check` + `ruff format --check`
- **typecheck** — `mypy --strict src/navi_sanitize/`
- **test** — pytest across Python 3.12 + 3.13, `--benchmark-disable` (matrix → aggregator)
- **security** — `pip-audit` dependency vulnerability scan
- **quality-gate** — gates on all four above (org ruleset required check)
- **build** — gates on all four required checks; builds wheel, smoke-tests imports (`clean`, `walk`, `jinja2_escaper`, `path_escaper`), uploads artifact

Additional security workflows: Semgrep SAST, CodeQL (`python` + `actions` via org GHAS), OpenSSF Scorecard.

**Fuzz testing** (`.github/workflows/fuzz.yml`) — Atheris fuzzing of `fuzz_clean` and `fuzz_walk` targets, runs on push/PR and weekly schedule (Wednesday 03:00 UTC). Uploads crash artifacts on failure.

Benchmarks run via manual dispatch only (`.github/workflows/benchmark.yml`).

## Architecture

Uses `src/` layout (`src/navi_sanitize/`). Internal modules prefixed with `_`.

### Public API (`__init__.py`)

Eight exports: `clean(text, *, escaper=None) -> str`, `walk(data, *, escaper=None, max_depth=128) -> T`, escapers (`jinja2_escaper`, `path_escaper`), `Escaper = Callable[[str], str]`, and opt-in utilities (`decode_evasion`, `detect_scripts`, `is_mixed_script`).

### Pipeline (`_pipeline.py`)

Six stages in strict order — reordering breaks security:

1. **Null byte removal** — strip `\x00` (prevents C-extension truncation)
2. **Invisible character stripping** — single compiled regex covering 492 chars across 9 categories: zero-width, format/control, variation selectors, variation selector supplement, Mongolian FVS, Unicode Tag block (`U+E0000`-`U+E007F`), bidirectional controls, C0 controls, and C1 controls
3. **NFKC normalization** — collapses fullwidth ASCII and compatibility forms
4. **Homoglyph replacement** — NFD decomposition then character-by-character scan against 66-pair map in `_homoglyphs.py`
5. **Re-NFKC** (conditional) — re-normalize after homoglyph replacement to ensure idempotency
6. **Escaper** (optional) — pluggable `Callable[[str], str]` runs last

Stages 1–5 each return `(cleaned_string, count)` where `count` is an `int` for removals, replacements, or normalization changes. Stage 6 (escaper) is a `Callable[[str], str]` that returns a bare `str`. Stages have no side effects — the orchestrator logs.

### Data files

- `_homoglyphs.py` — 66 pairs: Cyrillic, Greek, Armenian, Cherokee, Cyrillic Extended, Latin Extended, and typographic lookalikes
- `_invisible.py` — zero-width, format/control (soft hyphen, thin/hair space, line/paragraph separators, etc.), variation selectors, variation selector supplement, Mongolian FVS, Unicode Tag block, bidirectional controls, C0 controls, and C1 controls

### Escapers (`escapers/`)

- `_jinja2.py` — single-pass regex backslash-escapes `{{`, `}}`, `{%`, `%}`, `{#`, `#}` and brace runs of 2+ (handles triple braces)
- `_path.py` — strips `../`, `./`, leading `/`, and embedded `..` within segments (handles null-byte concatenation artifacts)

## Conventions

- **Conventional commits:** `feat:`, `fix:`, `test:`, `chore:`, `docs:`
- **Line length:** 100 (ruff + mypy strict)
- **TDD:** write failing test → implement → verify → commit
- **Test oracle:** for inputs covered by navi-bootstrap's adversarial suite, `clean(text, escaper=jinja2_escaper)` must match navi-bootstrap's `_sanitize_string(text, escape_jinja=True)` exactly
- **Warnings include counts:** `"Stripped 3 invisible character(s)"` not `"Stripped invisible character(s)"`
- **`NullHandler` on library logger** — app configures handlers, not the library
- **`walk()` is non-mutating** — original data never modified; PEP 695 `def walk[T]()` for return type; default `max_depth=128`; performs a single iterative copy-and-sanitize pass; escaper output is NOT re-sanitized (trust boundary)
- **No remote push** without explicit approval — local only until told otherwise

## Gotchas

- **`ruff` rules `RUF001`/`RUF003`** fire on intentional Cyrillic/Greek/Armenian/Cherokee in test and data files — use `# ruff: noqa: RUF001, RUF003` or `# ruff: noqa: RUF003` at top of those files
- **Tag block range starts at `U+E0000`** (includes the deprecated LANGUAGE TAG character)
- **pytest-benchmark `pedantic()`** required for large payloads (100KB) — standard mode runs too many iterations
- **No CLI, no config files, no framework dependencies** — this is a library only
- **No LLM prompt escaper** — vendor syntax moves too fast; pluggable design lets users build their own
- **`walk()` default `max_depth=128`** — existing tests for deep nesting must pass `max_depth=` explicitly if depth exceeds 128
- **Escaper trust boundary** — escaper output is NOT re-sanitized; custom escapers can re-introduce hostile characters by design
