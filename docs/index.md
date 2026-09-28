---
hide:
  - navigation
  - toc
---

# navi-sanitize

**Deterministic sanitization for untrusted text.** Strips invisible and control characters, normalizes compatibility forms and replaces a curated set of homoglyphs before your code compares, stores, logs or renders the text. Python 3.12+, standard library only, no ML.

[Get Started](getting-started/quickstart.md){ .md-button .md-button--primary }
[API Reference](reference/api.md){ .md-button }

---

## See the invisible

```python
from navi_sanitize import clean

evil = "system\u200b\u200cprompt"  # looks like "systemprompt" but has 2 hidden chars
len(evil)    # 14
clean(evil)  # 'systemprompt'
```

## What it does

- **A fixed pipeline** --- null bytes, 492 invisible/format/control characters, NFKC normalization, 66 homoglyph replacements and re-normalization, then an optional escaper you choose
- **Deterministic** --- the same input always gives the same output; property and fuzz tests check that `clean()` is idempotent
- **No dependencies** --- standard library only
- **Nested data** --- `walk()` sanitizes every string in dicts and lists, keys included, into new containers
- **Content-free logging** --- warnings report counts ("Stripped 3 invisible character(s)"), never input text
- **Opt-in helpers** --- `decode_evasion()` for nested URL/HTML/hex encodings, `detect_scripts()` / `is_mixed_script()` for mixed-script signals; none run automatically

## What it does not do

It changes some legitimate text, its homoglyph map is deliberately small, and its escapers are narrow helpers rather than sandboxes. It does not replace HTML escaping, parameterized SQL, template autoescaping, path confinement or prompt-injection defenses. The [threat model](explanation/threat-model.md) lists the limits.

## Quick start

```bash
pip install navi-sanitize
```

```python
from navi_sanitize import clean

clean("Неllo Wоrld")      # 'Hello World' (Cyrillic Н and о replaced)
clean("price:\u200b 0")   # 'price: 0' (zero-width space stripped)
clean("file\x00.txt")     # 'file.txt' (null byte removed)
```

## Documentation

| Page | Description |
|------|-------------|
| [Getting Started](getting-started/quickstart.md) | Installation, basic usage, logging |
| [Writing Custom Escapers](how-to/writing-custom-escapers.md) | The escaper contract and examples |
| [Why This Matters](explanation/why-this-matters.md) | Where character-level sanitization helps |
| [Pipeline Architecture](explanation/pipeline-architecture.md) | The stages in order, and why the order matters |
| [Threat Model](explanation/threat-model.md) | What is covered, what is not, what changes |
| [Performance](explanation/performance.md) | Measured costs and hot-path advice |
| [Comparison](explanation/comparison.md) | How it relates to other text tools |
| [API Reference](reference/api.md) | Every public function and type |
| [Character Reference](reference/character-reference.md) | Full invisible-character and homoglyph tables |
| [Changelog](reference/changelog.md) | Release history |

## Links

- [GitHub Repository](https://github.com/Project-Navi/navi-sanitize)
- [Issue Tracker](https://github.com/Project-Navi/navi-sanitize/issues)
- [PyPI](https://pypi.org/project/navi-sanitize/)
