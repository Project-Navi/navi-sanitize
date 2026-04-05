---
hide:
  - navigation
  - toc
---

# navi-sanitize

**Deterministic input sanitization for untrusted text** --- invisible characters, homoglyphs, and encoding tricks, handled before your code sees them. Zero dependencies, no ML. Legitimate Unicode preserved by design.

navi-sanitize removes invisible attacks from untrusted text before it reaches your application. It doesn't detect attacks --- it removes them. Implements the pipeline recommended by the [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).

[Get Started](getting-started/quickstart.md){ .md-button .md-button--primary }
[API Reference](reference/api.md){ .md-button }

---

## See the invisible

```python
evil = "system\u200b\u200cprompt"  # looks like "systemprompt" but has 2 hidden chars
len(evil)           # 14 (not 12!)
clean(evil)         # "systemprompt" — hidden chars stripped
```

---

## Features

- **6-stage pipeline** --- null bytes, invisible characters, NFKC normalization, homoglyph replacement, re-NFKC for idempotency, pluggable escaper
- **OWASP aligned** --- implements the NFKC + zero-width + control character sanitization recommended by the LLM Prompt Injection Prevention Cheat Sheet
- **Only maintained option** --- both [confusable_homoglyphs](https://github.com/vhf/confusable_homoglyphs) and [homoglyphs](https://github.com/life4/homoglyphs) are archived; navi-sanitize is the only maintained Python library covering homoglyph replacement
- **Deterministic** --- same input always produces the same output; no probabilistic models, no heuristics
- **Zero dependencies** --- Python 3.12+ stdlib only; no third-party dependency risk
- **Pluggable escapers** --- built-in Jinja2 and path traversal escapers; write your own in three lines
- **Recursive sanitization** --- `walk()` sanitizes every string in nested dicts and lists
- **Transparent logging** --- warnings include counts ("Stripped 3 invisible character(s)")
- **Opt-in utilities** --- `decode_evasion()` for nested encoding, `detect_scripts()` / `is_mixed_script()` for mixed-script analysis --- not enabled by default

## Quick Start

```bash
pip install navi-sanitize
```

```python
from navi_sanitize import clean

clean("Неllo Wоrld")      # "Hello World" — Cyrillic Н/о replaced
clean("price:\u200b 0")   # "price: 0" — zero-width space stripped
clean("file\x00.txt")     # "file.txt" — null byte removed
```

## Documentation

| Page | Description |
|------|-------------|
| [Why This Matters](explanation/why-this-matters.md) | Use cases: LLM pipelines, web apps, config ingestion, logs, anti-phishing |
| [Comparison](explanation/comparison.md) | How navi-sanitize compares to Unidecode, ftfy, confusable_homoglyphs, etc. |
| [Getting Started](getting-started/quickstart.md) | Installation, basic usage, logging setup |
| [API Reference](reference/api.md) | Complete function and type reference |
| [Pipeline Architecture](explanation/pipeline-architecture.md) | The 6 stages in depth, with data flow |
| [Threat Model](explanation/threat-model.md) | What's covered, what's not, design philosophy |
| [Writing Custom Escapers](how-to/writing-custom-escapers.md) | How to extend with your own escapers |
| [Character Reference](reference/character-reference.md) | Full invisible character and homoglyph tables |
| [Performance](explanation/performance.md) | Benchmarks and optimization tips |

## Links

- [GitHub Repository](https://github.com/Project-Navi/navi-sanitize)
- [Issue Tracker](https://github.com/Project-Navi/navi-sanitize/issues)
- [PyPI](https://pypi.org/project/navi-sanitize/)
