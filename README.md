# navi-sanitize

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

## License

MIT
