# navi-sanitize

[![CI](https://github.com/Project-Navi/navi-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/Project-Navi/navi-sanitize/actions/workflows/ci.yml)
[![Fuzz](https://github.com/Project-Navi/navi-sanitize/actions/workflows/fuzz.yml/badge.svg)](https://github.com/Project-Navi/navi-sanitize/actions/workflows/fuzz.yml)
[![codecov](https://codecov.io/gh/Project-Navi/navi-sanitize/branch/main/graph/badge.svg)](https://codecov.io/gh/Project-Navi/navi-sanitize)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-green.svg)](https://www.python.org/)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Project-Navi/navi-sanitize/badge)](https://scorecard.dev/viewer/?uri=github.com/Project-Navi/navi-sanitize)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Deterministic input sanitization for untrusted text. Zero dependencies, zero false positives.

```python
from navi_sanitize import clean

clean("Неllo Wоrld")  # "Hello World" — Cyrillic Н/о replaced
clean("price:\u200b 0")  # "price: 0" — zero-width space stripped
clean("file\x00.txt")  # "file.txt" — null byte removed
```

Opt-in utilities for deeper analysis: `decode_evasion()` peels nested URL/HTML/hex encodings, `detect_scripts()` and `is_mixed_script()` flag mixed-script spoofing.

## Why This Matters

Untrusted text contains invisible attacks: homoglyph substitution, zero-width characters, null bytes, fullwidth encoding, template/prompt injection delimiters. These bypass validation, poison templates, and fool humans.

navi-sanitize fixes the text before it reaches your application. It doesn't detect attacks — it removes them.

**LLM prompt pipelines** — User input flows into system prompts, RAG context, and tool calls. Invisible Unicode (tag block characters, bidi overrides) encodes instructions that tokenizers read but humans can't see. Homoglyphs bypass keyword filters. navi-sanitize strips these vectors before text reaches the model, and the pluggable escaper lets you add vendor-specific prompt escaping on top.

**Web applications** — Jinja2 SSTI, path traversal, and fullwidth encoding bypasses are well-known but tedious to cover manually. A single `clean(user_input, escaper=jinja2_escaper)` call handles homoglyph-disguised payloads like `{{ cоnfig }}` (Cyrillic `о`) that naive escaping misses.

**Config and data ingestion** — YAML, TOML, and JSON parsed from untrusted sources can carry null bytes that truncate C-extension processing, zero-width characters that break key matching, and homoglyphs that create near-duplicate keys. `walk(parsed_config)` sanitizes every string in a nested structure in one call.

**Log analysis and SIEM** — Attackers embed bidi overrides and zero-width characters in log entries to hide indicators of compromise from analysts and pattern-matching tools. Sanitizing log data on ingest ensures what you search is what's actually there.

**Identity and anti-phishing** — `pаypal.com` (Cyrillic `а`) renders identically to `paypal.com` in most fonts. Homoglyph replacement normalizes display names, URLs, and email addresses to catch spoofing that visual inspection misses.

## How It Compares

navi-sanitize is the only library that combines invisible character stripping, homoglyph replacement, NFKC normalization, and pluggable escaping in a single zero-dependency pipeline. Existing tools solve pieces of this problem:

| | navi-sanitize | Unidecode / anyascii | confusable_homoglyphs | ftfy | MarkupSafe / nh3 |
|---|---|---|---|---|---|
| **Purpose** | Security sanitization | ASCII transliteration | Homoglyph detection | Encoding repair | HTML escaping |
| **Invisible chars** | Strips 411 (bidi, tag block, ZW, VS) | Incidental | No | Partial (preserves bidi, ZW, VS) | No |
| **Homoglyphs** | Replaces 54 curated pairs | Transliterates all non-ASCII | Detects only (no replace) | No | No |
| **NFKC** | Yes | No | No | NFC (NFKC optional) | No |
| **Null bytes** | Yes | No | No | No | No |
| **Preserves Unicode** | Yes (CJK, Arabic, emoji intact) | No (destroys all non-ASCII) | Yes | Yes | Yes |
| **Pluggable escaper** | Yes | No | No | No | N/A (HTML-specific) |
| **Dependencies** | Zero | Zero | Zero | wcwidth | C ext / Rust ext |

**Key differences:**

- **Unidecode / anyascii** transliterate *all* non-ASCII to Latin. They turn `"` into `"Zhong"` and Cyrillic sentences into gibberish. navi-sanitize normalizes only the 54 highest-risk lookalikes and leaves legitimate Unicode intact.
- **confusable_homoglyphs** uses the full Unicode Consortium confusables dataset (thousands of pairs) but only *detects* — you'd need to write your own replacement layer. It's also archived.
- **ftfy** is complementary, not competing. It fixes encoding corruption and explicitly *preserves* bidi overrides and zero-width characters that navi-sanitize strips. Different threat model.
- **MarkupSafe / nh3** handle HTML structure; navi-sanitize handles the character-level content *inside* that structure. They compose naturally.
- **pydantic / cerberus** are validation frameworks — call `navi_sanitize.clean()` inside a pydantic `AfterValidator` or cerberus coercion chain for validated, sanitized output.

## Pipeline

Every string passes through stages in order. Each stage returns clean output and a warning if it changed anything.

| Stage | What it does |
|-------|-------------|
| Null bytes | Strip `\x00` |
| Invisibles | Strip zero-width, Unicode Tag block, bidi controls |
| NFKC | Normalize fullwidth ASCII to standard ASCII |
| Homoglyphs | Replace Cyrillic/Greek lookalikes with Latin equivalents |
| Re-NFKC | Re-normalize after homoglyph replacement (ensures idempotency) |
| **Escaper** | Pluggable — you choose what to escape for |

The first five stages are universal. The escaper is where you tell the pipeline what the output is for.

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

## Framework Integration

```python
# Pydantic — validate then sanitize
from typing import Annotated
from pydantic import BaseModel, AfterValidator
from navi_sanitize import clean

SafeStr = Annotated[str, AfterValidator(clean)]

class UserInput(BaseModel):
    name: SafeStr
    bio: SafeStr

# FastAPI — sanitize at the edge
from fastapi import Depends, Query
from navi_sanitize import clean

def safe_query(q: str = Query()) -> str:
    return clean(q)

@app.get("/search")
def search(q: str = Depends(safe_query)):
    return {"results": find(q)}

# Jinja2 — sanitize before rendering
from navi_sanitize import clean, jinja2_escaper

safe_context = {k: clean(v, escaper=jinja2_escaper) for k, v in user_data.items()}
template.render(**safe_context)
```

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

## Opt-in Utilities

**These utilities are not part of `clean()` and are never run automatically.** You must call them explicitly.

```python
from navi_sanitize import decode_evasion, clean, detect_scripts, is_mixed_script, path_escaper

# Double-encoded path traversal
raw = "%252e%252e%252fetc%252fpasswd"

# 1. Peel nested encodings (URL → HTML entities → hex escapes)
peeled = decode_evasion(raw)           # "../etc/passwd"

# 2. Sanitize through the universal pipeline
cleaned = clean(peeled, escaper=path_escaper)  # "etc/passwd"

# 3. Check for mixed-script spoofing (useful on raw or pre-clean input)
if is_mixed_script(raw) or is_mixed_script(peeled):
    flag_for_review(raw)
```

- **`decode_evasion(text, *, max_layers=3)`** — iterative URL/HTML/hex decoding; stops when a pass produces no change
- **`detect_scripts(text)`** — returns script buckets present in text (`latin`, `cyrillic`, `greek`, etc.)
- **`is_mixed_script(text)`** — `True` when 2+ scripts detected

Script detection can be applied pre-clean too — most useful on raw input for phishing detection.

## What This Doesn't Do

navi-sanitize operates at the character level. It does **not** cover:

- **HTML/XSS** — use your template engine's auto-escaping (`markupsafe.escape()`, `nh3.clean()`)
- **SQL injection** — use parameterized queries
- **Schema validation** — use pydantic, cerberus, or similar (they compose with `clean()`)
- **LLM prompt injection** — vendor syntax is a moving target; write a custom escaper

These are different problems with mature, purpose-built solutions. navi-sanitize handles what they don't: the invisible, character-level content that slips past them.

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
