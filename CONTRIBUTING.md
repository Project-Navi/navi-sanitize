# Contributing to navi-sanitize

Thanks for your interest in contributing. This guide covers the development workflow.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/Project-Navi/navi-sanitize.git
cd navi-sanitize

# Install dependencies (requires uv)
uv sync

# Install pre-commit hooks
pre-commit install
```

## Running Tests

```bash
# Full test suite
uv run pytest tests/ -v --benchmark-disable

# Single test file
uv run pytest tests/test_clean.py -v --benchmark-disable

# Single test
uv run pytest tests/test_clean.py::test_name -v --benchmark-disable

# With coverage
uv run coverage run -m pytest tests/ --benchmark-disable
uv run coverage report --include='src/navi_sanitize/**'
```

## Code Quality

All checks run automatically via pre-commit hooks and CI:

```bash
# Lint
uv run ruff check src/ tests/

# Format
uv run ruff format --check src/ tests/

# Type check
uv run mypy --strict src/navi_sanitize/

# Run all pre-commit hooks
pre-commit run --all-files
```

## Commit Messages

This project uses [conventional commits](https://www.conventionalcommits.org/):

- `feat:` — new feature
- `fix:` — bug fix
- `test:` — adding or updating tests
- `docs:` — documentation changes
- `ci:` — CI/CD changes
- `chore:` — maintenance tasks
- `refactor:` — code refactoring
- `perf:` — performance improvement

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Write or update tests for your changes
3. Ensure all checks pass (`pre-commit run --all-files`)
4. Keep PRs focused — one concern per PR
5. Open the PR against `main`

## Testing Philosophy

- **TDD:** write a failing test first, then implement
- **Coverage:** maintain 100% coverage on `src/navi_sanitize/`
- **Adversarial tests:** if adding or modifying a pipeline stage, add attack vectors to `tests/test_adversarial.py` or `tests/test_bypass_attempts.py`
- **Warnings include counts:** `"Stripped 3 invisible character(s)"` not `"Stripped invisible character(s)"`

## Architecture Notes

- `src/` layout with internal modules prefixed `_`
- Zero external dependencies — stdlib only
- Pipeline stage order matters — see the [wiki](https://github.com/Project-Navi/navi-sanitize/wiki/Pipeline-Architecture)
- `ruff` rules `RUF001`/`RUF003` are intentionally suppressed in test and data files containing non-Latin characters

## Reporting Bugs

Open an issue on [GitHub Issues](https://github.com/Project-Navi/navi-sanitize/issues). Include:

- Python version
- Minimal reproduction
- Expected vs actual behavior

## Security Vulnerabilities

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for reporting instructions.
