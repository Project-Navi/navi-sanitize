# CLAUDE.md

Guidance for Claude Code in this repository. [CONTRIBUTING.md](CONTRIBUTING.md) is the canonical maintainer guide (setup, the checks CI runs, conventions, release path); read it first.

navi-sanitize is a zero-dependency Python 3.12+ library for deterministic sanitization of untrusted text. Library only: no CLI, config files, framework dependencies or LLM prompt escaper.

## Map

- `src/navi_sanitize/_pipeline.py` --- `clean()` and `walk()`
- `src/navi_sanitize/_invisible.py` (492 characters), `_homoglyphs.py` (66 pairs) --- data
- `src/navi_sanitize/_decode.py`, `_scripts.py` --- opt-in `decode_evasion()`, `detect_scripts()`, `is_mixed_script()`
- `src/navi_sanitize/escapers/` --- `jinja2_escaper`, `path_escaper`
- `scripts/verify_dist.py`, `scripts/build_docs.py` --- release and docs checks run by CI

## Constraints that are easy to break

- Pipeline stage order is part of the contract; escaper output is never re-sanitized.
- Public exports, defaults, the Python floor and the zero-runtime-dependency rule change only by owner decision.
- Log messages carry counts only, never input text, keys or values.
- `walk()` never modifies its input and stays iterative.
- No remote push without explicit approval.
