# navi-sanitize

[![CI](https://github.com/Project-Navi/navi-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/Project-Navi/navi-sanitize/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Project-Navi/navi-sanitize/graph/badge.svg?token=9Vr26NV2Fn)](https://codecov.io/gh/Project-Navi/navi-sanitize)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Project-Navi/navi-sanitize/badge)](https://scorecard.dev/viewer/?uri=github.com/Project-Navi/navi-sanitize)
[![PyPI](https://img.shields.io/pypi/v/navi-sanitize)](https://pypi.org/project/navi-sanitize/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Deterministic sanitization of untrusted text for Python 3.12+, with no dependencies.
`clean()` removes null bytes and 492 invisible, formatting and control characters,
applies NFKC normalization, and replaces 66 curated homoglyphs (Cyrillic, Greek,
Armenian, Cherokee, Latin Extended and typographic lookalikes) with ASCII. An optional escaper then
prepares the result for one destination. It normalizes characters; it is not a
complete defense against prompt, template, HTML, SQL or path injection.

```
pip install navi-sanitize
```

```python
from navi_sanitize import clean, path_escaper, walk

clean("Неllo Wоrld")                             # 'Hello World' (Cyrillic Н, о)
clean("pass\u200bword\x00")                      # 'password'
clean("ｆｕｌｌ ｗｉｄｔｈ")                     # 'full width'
clean("../../etc/passwd", escaper=path_escaper)  # 'etc/passwd'
walk({"n\u0430me": ["te\u200bst"]})              # {'name': ['test']} (a new dict)
```

`walk()` sanitizes every string in nested dicts and lists, keys included, and returns
new containers. `decode_evasion()`, `detect_scripts()` and `is_mixed_script()` are
opt-in helpers that `clean()` never runs.

## Limits

- **Legitimate text changes.** Mapped letters are replaced inside real words
  (`clean("привет")` gives the mixed-script `'пpивeт'`), ZWJ emoji sequences split,
  variation selectors and tag characters go, Arabic/Hebrew directional marks are
  removed, and NFKC folds compatibility forms. Apply it to fields where that is acceptable.
- **The homoglyph map is small.** Other confusables pass through; `is_mixed_script()`
  on the raw input can flag some of them.
- **Escapers are narrow.** `jinja2_escaper` breaks up Jinja2's default delimiters; it
  is not a sandbox or an HTML escaper, so pass untrusted text to templates as data.
  `path_escaper` edits strings only: no directory confinement, symlink or drive-letter
  handling, and the result can be empty. Custom escaper output is not re-sanitized.
- **`walk()` is lossy for keys.** Keys that sanitize to the same string keep the last
  value and log a warning. Tuples, sets and other objects are returned unchanged.
- Changes are logged on the `navi_sanitize` logger as counts, never content.

## Documentation

[docs.projectnavi.ai/navi-sanitize](https://docs.projectnavi.ai/navi-sanitize/):
[quickstart](https://docs.projectnavi.ai/navi-sanitize/getting-started/quickstart/),
[API](https://docs.projectnavi.ai/navi-sanitize/reference/api/),
[threat model](https://docs.projectnavi.ai/navi-sanitize/explanation/threat-model/),
[custom escapers](https://docs.projectnavi.ai/navi-sanitize/how-to/writing-custom-escapers/),
[character tables](https://docs.projectnavi.ai/navi-sanitize/reference/character-reference/).

[Contributing](CONTRIBUTING.md) · [Security reports](SECURITY.md) (security@projectnavi.ai) ·
[Changelog](CHANGELOG.md) · MIT licensed
