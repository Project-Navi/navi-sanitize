# Getting Started

## Installation

```bash
pip install navi-sanitize
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add navi-sanitize
```

Requires Python 3.12 or later. No external dependencies.

## Where to start

**LLM pipelines.** Invisible characters and lookalikes can hide text from reviewers and keyword filters. Start with [the LLM pipeline example](https://github.com/Project-Navi/navi-sanitize/blob/main/examples/llm_pipeline.py) and [Pipeline Architecture](../explanation/pipeline-architecture.md). Sanitizing input does not stop prompt injection written in plain text.

**Web apps.** Pydantic `AfterValidator` and FastAPI `Depends` give one-line sanitization at the edge; see [the FastAPI/Pydantic example](https://github.com/Project-Navi/navi-sanitize/blob/main/examples/fastapi_pydantic.py).

**Security review.** Read the [Threat Model](../explanation/threat-model.md) and the [Character Reference](../reference/character-reference.md). The [whitepaper PDF](https://github.com/Project-Navi/navi-sanitize/blob/main/docs/whitepaper/navi-sanitize-whitepaper.pdf) is a March 2026 (v0.2.0) snapshot of the design rationale; where it differs from these pages, these pages describe current behavior.

## Basic Usage

### Sanitizing a Single String

```python
from navi_sanitize import clean

# Homoglyph: Cyrillic а looks identical to Latin a
clean("pаypal.com")  # 'paypal.com'

# Invisible characters hidden in text
clean("te\u200bst")  # 'test'

# Null byte
clean("file\x00.txt")  # 'file.txt'

# Fullwidth forms
clean("\uff41\uff44\uff4d\uff49\uff4e")  # 'admin'
```

### Using Escapers

An escaper runs last and prepares the cleaned text for one destination:

```python
from navi_sanitize import clean, path_escaper

# Lexical path cleanup (not directory confinement)
clean("../../../etc/passwd", escaper=path_escaper)  # 'etc/passwd'
```

`jinja2_escaper` exists for the rare case where untrusted text must become part of Jinja2 template *source*. The normal, safer integration is to keep templates trusted and pass untrusted values as data; Jinja2 does not evaluate context values:

```python
from jinja2 import Environment
from navi_sanitize import clean

env = Environment(autoescape=True)
template = env.from_string("Hello {{ name }}")
template.render(name=clean(user_name))  # the value is data, never template code
```

### Sanitizing Nested Data

`walk()` sanitizes every string in a dict/list structure, including dict keys:

```python
from navi_sanitize import walk

untrusted = {
    "name": "pаypal",          # Cyrillic а
    "paths": ["../secret", "safe.txt"],
    "count": 42,               # non-strings pass through
    "nested": {
        "value": "te\u200bst"  # zero-width space
    },
}

clean_data = walk(untrusted)
# {'name': 'paypal', 'paths': ['../secret', 'safe.txt'], 'count': 42, 'nested': {'value': 'test'}}
```

The input is never modified. `walk()` builds new dicts and lists (subclasses such as `OrderedDict` come back as plain `dict`/`list`) and shares every other object with the input:

- `str` --- sanitized through the full pipeline
- `dict` --- keys and values sanitized
- `list` --- elements sanitized
- `tuple`, `set`, `frozenset`, `bytes`, numbers, `None`, other objects --- returned as-is, not traversed

If two keys sanitize to the same string, the last value wins and a warning with the collision count is logged. Validate keys yourself where distinct key identity matters.

## Logging

navi-sanitize logs to the `navi_sanitize` logger and registers a `NullHandler`, so nothing appears until you configure logging:

```python
import logging

logging.basicConfig(level=logging.WARNING)

from navi_sanitize import clean

clean("pаypal.com")
# WARNING:navi_sanitize:Replaced 1 homoglyph(s) in value
```

Messages carry counts only, never input text:

- `Removed 2 null byte(s) from value`
- `Stripped 3 invisible character(s) from value`
- `Normalized 1 fullwidth/compatibility character(s) in value`
- `Replaced 1 homoglyph(s) in value`
- `Decoded 2 encoding layer(s) from value` (from `decode_evasion()`)
- `walk() dict key collision: 1 key(s) sanitized to an existing key; last value kept`
- `walk() input exceeds max_depth=128; continuing to sanitize`

All are `WARNING` level. High-volume callers can configure the library logger like any other. For example, drop the per-value messages but keep the `walk()` warnings:

```python
import logging

class KeepWalkWarnings(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage().startswith("walk()")

logging.getLogger("navi_sanitize").addFilter(KeepWalkWarnings())
```

Or silence it entirely with `logging.getLogger("navi_sanitize").setLevel(logging.ERROR)`.

## Opt-in Utilities

**These are not part of `clean()` and never run automatically.**

### Decoding Nested Encodings

`decode_evasion()` peels URL percent-encoding, HTML entities and `\xHH` escapes, up to three passes by default. It does not decode base64 or other formats.

```python
from navi_sanitize import clean, decode_evasion, path_escaper

raw = "%252e%252e%252fetc%252fpasswd"   # double-encoded "../etc/passwd"

peeled = decode_evasion(raw)                    # '../etc/passwd'
cleaned = clean(peeled, escaper=path_escaper)   # 'etc/passwd'
```

### Mixed-Script Detection

`detect_scripts()` returns the set of script buckets it recognizes in a string; `is_mixed_script()` is `True` when there are two or more:

```python
from navi_sanitize import detect_scripts, is_mixed_script

detect_scripts("paypal.com")   # {'latin'}
detect_scripts("pаypal.com")   # {'latin', 'cyrillic'}

is_mixed_script("paypal.com")  # False
is_mixed_script("pаypal.com")  # True
```

Run detection on **raw** input: `clean()` replaces mapped homoglyphs, which removes the signal. It is a heuristic over eight buckets, not a Unicode script classifier.
