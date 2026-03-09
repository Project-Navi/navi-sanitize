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

## Quick Start by Use Case

**Building LLM pipelines?** User input flows into prompts, RAG context, and tool calls. Invisible Unicode encodes instructions tokenizers read but humans can't see. Start with [the LLM pipeline example](https://github.com/Project-Navi/navi-sanitize/blob/main/examples/llm_pipeline.py), then read [Pipeline Architecture](../explanation/pipeline-architecture.md) to understand what's stripped.

**Securing a web app?** Pydantic `AfterValidator` and FastAPI `Depends` give you one-line sanitization at the edge. See [the FastAPI/Pydantic example](https://github.com/Project-Navi/navi-sanitize/blob/main/examples/fastapi_pydantic.py) and the [Writing Custom Escapers](../how-to/writing-custom-escapers.md) guide.

**Evaluating for AppSec?** Start with the [Threat Model](../explanation/threat-model.md) --- it documents what's covered, what's not, and why. The [Character Reference](../reference/character-reference.md) has the complete tables. The [whitepaper PDF](https://github.com/Project-Navi/navi-sanitize/blob/main/docs/whitepaper/navi-sanitize-whitepaper.pdf) covers design rationale and testing methodology.

## Basic Usage

### Sanitizing a Single String

```python
from navi_sanitize import clean

# Homoglyph attack — Cyrillic а looks identical to Latin a
clean("pаypal.com")  # "paypal.com"

# Invisible characters hidden in text
clean("te\u200bst")  # "test" — zero-width space removed

# Null byte injection
clean("file\x00.txt")  # "file.txt"

# Fullwidth encoding bypass
clean("\uff41\uff44\uff4d\uff49\uff4e")  # "admin" — NFKC normalized
```

### Using Escapers

Escapers run as the final pipeline stage, providing context-specific escaping after universal sanitization:

```python
from navi_sanitize import clean, jinja2_escaper, path_escaper

# Jinja2 template injection prevention
clean("{{ config }}", escaper=jinja2_escaper)
# "\\{\\{ config \\}\\}"

# Path traversal prevention
clean("../../../etc/passwd", escaper=path_escaper)
# "etc/passwd"

# No escaper — universal stages only
clean(user_input)
```

### Sanitizing Nested Data

Use `walk()` to recursively sanitize every string in a dict/list structure:

```python
from navi_sanitize import walk, jinja2_escaper

untrusted = {
    "name": "pаypal",         # Cyrillic а
    "paths": ["../secret", "safe.txt"],
    "count": 42,              # non-strings pass through
    "nested": {
        "value": "te\u200bst" # zero-width space
    }
}

clean_data = walk(untrusted)
# {
#     "name": "paypal",
#     "paths": ["../secret", "safe.txt"],
#     "count": 42,
#     "nested": {"value": "test"}
# }
```

`walk()` returns a deep copy --- the original data is never modified.

**Type behavior:**
- `str` --- sanitized through the full pipeline
- `dict` --- keys and values sanitized recursively
- `list` --- elements sanitized recursively
- `int`, `float`, `bool`, `None`, `bytes`, `tuple`, `set` --- passed through unchanged

## Logging

navi-sanitize uses Python's standard `logging` module. The library registers a `NullHandler` by default (per library best practice), so no output appears unless you configure logging:

```python
import logging

# See all sanitization warnings
logging.basicConfig(level=logging.WARNING)

from navi_sanitize import clean

clean("pаypal.com")
# WARNING:navi_sanitize:Replaced 1 homoglyph(s) in value
# Returns: "paypal.com"
```

Warnings include counts for traceability:
- `"Removed 2 null byte(s) from value"`
- `"Stripped 3 invisible character(s) from value"`
- `"Normalized fullwidth character(s) in value"`
- `"Replaced 1 homoglyph(s) in value"`

To capture warnings programmatically:

```python
import logging

logger = logging.getLogger("navi_sanitize")
logger.setLevel(logging.WARNING)
logger.addHandler(logging.StreamHandler())
```

## Opt-in Utilities

**These utilities are not part of `clean()` and are never run automatically.** They are standalone functions you compose with the pipeline yourself.

### Decoding Nested Evasion

Attackers nest URL, HTML entity, and hex encodings to sneak payloads past single-layer decoders. `decode_evasion()` peels these layers iteratively before `clean()` runs:

```python
from navi_sanitize import decode_evasion, clean, path_escaper

# Double-encoded path traversal
raw = "%252e%252e%252fetc%252fpasswd"

# 1. Peel encoding layers
peeled = decode_evasion(raw)                    # "../../etc/passwd"

# 2. Sanitize
cleaned = clean(peeled, escaper=path_escaper)   # "etc/passwd"
```

### Mixed-Script Detection

`detect_scripts()` returns the script buckets present in a string. `is_mixed_script()` is a convenience wrapper that returns `True` when two or more scripts are found --- useful for flagging homoglyph-based phishing:

```python
from navi_sanitize import detect_scripts, is_mixed_script

detect_scripts("paypal.com")   # {"latin"}
detect_scripts("pаypal.com")  # {"latin", "cyrillic"} — Cyrillic а

is_mixed_script("paypal.com")  # False
is_mixed_script("pаypal.com") # True — phishing candidate
```

Detection is most useful on **raw** input (before `clean()`), since `clean()` replaces homoglyphs and the mixed-script signal disappears.
