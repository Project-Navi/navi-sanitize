# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

navi-sanitize is a standalone, zero-dependency Python library extracted from navi-bootstrap. It provides deterministic input sanitization for untrusted text — no ML, no false positives. Python 3.12+, stdlib only.

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

GitHub Actions runs on push to `main` and all PRs. Four parallel jobs:

- **lint** — `ruff check` + `ruff format --check`
- **typecheck** — `mypy --strict src/navi_sanitize/`
- **test** — pytest across Python 3.12 + 3.13, `--benchmark-disable`
- **build** — gates on all three above; builds wheel, smoke-tests public API, uploads artifact

Benchmarks run via manual dispatch only (`.github/workflows/benchmark.yml`).

## Architecture

Uses `src/` layout (`src/navi_sanitize/`). Internal modules prefixed with `_`.

### Public API (`__init__.py`)

Three exports: `clean(text, *, escaper=None) -> str`, `walk(data, *, escaper=None) -> T`, and escapers (`jinja2_escaper`, `path_escaper`). `Escaper = Callable[[str], str]`.

### Pipeline (`_pipeline.py`)

Five stages in strict order — reordering breaks security:

1. **Null byte removal** — strip `\x00` (prevents C-extension truncation)
2. **Invisible character stripping** — single compiled regex covering zero-width chars, format/control chars, variation selectors, Unicode Tag block (`U+E0001`-`U+E007F`), and bidi overrides
3. **NFKC normalization** — collapses fullwidth ASCII and compatibility forms
4. **Homoglyph replacement** — character-by-character scan against 51-pair map in `_homoglyphs.py`
5. **Escaper** (optional) — pluggable `Callable[[str], str]` runs last

Each stage returns `(cleaned_string, changed: bool)`. Stages have no side effects — the orchestrator logs.

### Data files

- `_homoglyphs.py` — 51 pairs: Cyrillic, Greek, Armenian, Cherokee, and typographic lookalikes
- `_invisible.py` — zero-width, format/control (soft hyphen, thin/hair space, line/paragraph separators, etc.), variation selectors, Tag block, and bidi character sets

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
- **`walk()` uses `deepcopy`** — original data never modified; PEP 695 `def walk[T]()` for return type
- **No remote push** without explicit approval — local only until told otherwise

## Gotchas

- **`ruff` rules `RUF001`/`RUF003`** fire on intentional Cyrillic/Greek/Armenian/Cherokee in test and data files — use `# ruff: noqa: RUF001, RUF003` or `# ruff: noqa: RUF003` at top of those files
- **Tag block range starts at `U+E0001`**, not `U+E0000`
- **pytest-benchmark `pedantic()`** required for large payloads (100KB) — standard mode runs too many iterations
- **No CLI, no config files, no framework dependencies** — this is a library only
- **No LLM prompt escaper** — vendor syntax moves too fast; pluggable design lets users build their own
