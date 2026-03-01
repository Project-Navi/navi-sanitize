# navi-sanitize

[![CI](https://github.com/Project-Navi/navi-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/Project-Navi/navi-sanitize/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-green.svg)](https://www.python.org/)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Project-Navi/navi-sanitize/badge)](https://scorecard.dev/viewer/?uri=github.com/Project-Navi/navi-sanitize)

Input sanitization pipeline for untrusted text. Bytes in, clean bytes out.

```python
from navi_sanitize import clean

clean("Неllo Wоrld")  # "Hello World" — Cyrillic Н/о replaced
clean("price:\u200b 0")  # "price: 0" — zero-width space stripped
clean("file\x00.txt")  # "file.txt" — null byte removed
```

## Why

Untrusted text contains invisible attacks: homoglyph substitution, zero-width characters, null bytes, fullwidth encoding, template/prompt injection delimiters. These bypass validation, poison templates, and fool humans.

navi-sanitize fixes the text before it reaches your application. It doesn't detect attacks — it removes them.

## Pipeline

Every string passes through stages in order. Each stage returns clean output and a warning if it changed anything.

| Stage | What it does |
|-------|-------------|
| Null bytes | Strip `\x00` |
| Invisibles | Strip zero-width, Unicode Tag block, bidi controls |
| NFKC | Normalize fullwidth ASCII to standard ASCII |
| Homoglyphs | Replace Cyrillic/Greek lookalikes with Latin equivalents |
| **Escaper** | Pluggable — you choose what to escape for |

The first four stages are universal. The escaper is where you tell the pipeline what the output is for.

## Escapers

```python
from navi_sanitize import clean, jinja2_escaper, path_escaper

# For Jinja2 templates
clean("{{ malicious }}", escaper=jinja2_escaper)

# For filesystem paths
clean("../../etc/passwd", escaper=path_escaper)

# For LLM prompts — bring your own
clean(user_input, escaper=my_prompt_escaper)

# No escaper — just the universal stages
clean(user_input)
```

An escaper is a function: `str -> str`. Write one in three lines.

## Install

```
pip install navi-sanitize
```

## Walk untrusted data structures

```python
from navi_sanitize import walk

# Recursively sanitize every string in a dict/list
spec = walk(untrusted_json)
```

## Warnings

The pipeline never errors. It always produces output. When it changes something, it logs a warning.

```python
import logging
logging.basicConfig()

clean("pаypal.com")
# WARNING:navi_sanitize: Replaced 1 homoglyph(s) in value
# Returns: "paypal.com"
```

## Performance

Measured on Python 3.12, single thread. `clean()` is the per-string cost; `walk()` includes `deepcopy`.

| Scenario | Mean | Ops/sec |
|----------|------|---------|
| `clean()` — short, clean text (no-op) | 2.8 us | 358K |
| `clean()` — short, hostile (all stages fire) | 67 us | 15K |
| `clean()` — 13KB clean text | 810 us | 1.2K |
| `clean()` — 10KB hostile text | 449 us | 2.2K |
| `clean()` — 100KB hostile payload | 5.7 ms | 176 |
| `walk()` — 100-item nested dict, clean | 537 us | 1.9K |
| `walk()` — 100-item nested dict, hostile | 6.9 ms | 144 |

## License

MIT
