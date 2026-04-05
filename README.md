# navi-sanitize

[![Tests](https://github.com/Project-Navi/navi-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/Project-Navi/navi-sanitize/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Project-Navi/navi-sanitize/actions/workflows/codeql.yml/badge.svg)](https://github.com/Project-Navi/navi-sanitize/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/Project-Navi/navi-sanitize/graph/badge.svg?token=9Vr26NV2Fn)](https://codecov.io/gh/Project-Navi/navi-sanitize)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Project-Navi/navi-sanitize/badge)](https://scorecard.dev/viewer/?uri=github.com/Project-Navi/navi-sanitize)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![PyPI](https://img.shields.io/pypi/v/navi-sanitize)](https://pypi.org/project/navi-sanitize/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Deterministic input sanitization for untrusted text — invisible characters, homoglyphs, and encoding tricks, handled before your code sees them. Zero dependencies, no ML. Legitimate Unicode preserved by design.

```
pip install navi-sanitize
```

**[Documentation](https://project-navi.github.io/navi-sanitize/)** · [Getting Started](https://project-navi.github.io/navi-sanitize/getting-started/quickstart/) · [API Reference](https://project-navi.github.io/navi-sanitize/reference/api/) · [Threat Model](https://project-navi.github.io/navi-sanitize/explanation/threat-model/)

```python
from navi_sanitize import clean

clean("Неllo Wоrld")  # "Hello World" — Cyrillic Н/о replaced
clean("price:\u200b 0")  # "price: 0" — zero-width space stripped
clean("file\x00.txt")  # "file.txt" — null byte removed
```

See the invisible:

```python
evil = "system\u200b\u200cprompt"  # looks like "systemprompt" but has 2 hidden chars
len(evil)           # 14 (not 12!)
clean(evil)         # "systemprompt" — hidden chars stripped
```

Opt-in utilities for deeper analysis: `decode_evasion()` peels nested URL/HTML/hex encodings, `detect_scripts()` and `is_mixed_script()` flag mixed-script spoofing.

## Why This Matters

Untrusted text contains invisible attacks: homoglyph substitution, zero-width characters, null bytes, fullwidth encoding, template/prompt injection delimiters. These bypass validation, poison templates, and fool humans. Framework validators handle format and type — they don't handle Unicode deception. That's what this library is for.

navi-sanitize fixes the text before it reaches your application. It doesn't detect attacks — it removes them. Implements the NFKC + zero-width + control character pipeline recommended by the [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).

**LLM prompt pipelines** — Character-level attacks bypass LLM guardrails at [64–67% success rates](https://arxiv.org/html/2504.11168v1). Invisible Unicode encodes instructions tokenizers read but humans can't see. Homoglyphs bypass keyword filters. Sanitize before the model sees it.

**Web applications** — A single `clean(user_input, escaper=jinja2_escaper)` call handles homoglyph-disguised SSTI payloads like `{{ cоnfig }}` (Cyrillic `о`) that naive escaping misses.

**Identity and anti-phishing** — `pаypal.com` (Cyrillic `а`) renders identically to `paypal.com`. The only maintained Python homoglyph replacement library — both [confusable_homoglyphs](https://github.com/vhf/confusable_homoglyphs) and [homoglyphs](https://github.com/life4/homoglyphs) are archived.

**Log analysis** — Bidi overrides and zero-width chars hide IOCs from analysts. Sanitize on ingest so search matches reality.

**Config ingestion** — Null bytes truncate C-extension processing, zero-width chars break key matching. `walk(parsed_config)` sanitizes every string in a nested structure in one call.

These aren't theoretical risks — [CVE-2024-43093](https://nvd.nist.gov/vuln/detail/CVE-2024-43093) was an actively exploited Android zero-day using the exact fullwidth character bypass this pipeline prevents.

## How It Compares

navi-sanitize is the only library that combines invisible character stripping, homoglyph replacement, NFKC normalization, and pluggable escaping in a single zero-dependency pipeline. Existing tools solve pieces of this problem:

| | navi-sanitize | Unidecode / anyascii | confusable_homoglyphs | ftfy | MarkupSafe / nh3 |
|---|---|---|---|---|---|
| **Purpose** | Security sanitization | ASCII transliteration | Homoglyph detection | Encoding repair | HTML escaping |
| **Invisible chars** | Strips 492 (bidi, tag block, ZW, VS, C0/C1) | Incidental | No | Partial (preserves bidi, ZW, VS) | No |
| **Homoglyphs** | Replaces 66 curated pairs | Transliterates all non-ASCII | Detects only (no replace) | No | No |
| **NFKC** | Yes | No | No | NFC (NFKC optional) | No |
| **Null bytes** | Yes | No | No | No | No |
| **Preserves Unicode** | Yes (CJK, Arabic, emoji¹ intact) | No (destroys all non-ASCII) | Yes | Yes | Yes |
| **Pluggable escaper** | Yes | No | No | No | N/A (HTML-specific) |
| **Dependencies** | Zero | Zero | Zero | wcwidth | C ext / Rust ext |

¹ ZWJ (U+200D) is stripped as a zero-width character, which decomposes ZWJ emoji sequences (e.g. family emoji) into individual emoji. Single emoji are unaffected. Bidi formatting marks (U+061C, U+200E/F, etc.) used in Arabic/Hebrew are also stripped — correct rendering may require re-adding directional marks downstream.

**Key differences:**

- **Unidecode / anyascii** transliterate *all* non-ASCII to Latin. They turn `"` into `"Zhong"` and Cyrillic sentences into gibberish. navi-sanitize normalizes only the 66 highest-risk lookalikes and leaves legitimate Unicode intact.
- **confusable_homoglyphs** uses the full Unicode Consortium confusables dataset (thousands of pairs) but only *detects* — you'd need to write your own replacement layer. It's also archived.
- **ftfy** is complementary, not competing. It fixes encoding corruption and explicitly *preserves* bidi overrides and zero-width characters that navi-sanitize strips. Different threat model.
- **MarkupSafe / nh3** handle HTML structure; navi-sanitize handles the character-level content *inside* that structure. They compose naturally.
- **pydantic / cerberus** are validation frameworks — call `navi_sanitize.clean()` inside a pydantic `AfterValidator` or cerberus coercion chain for validated, sanitized output.

## Pipeline

Every string passes through stages in order. Each stage returns clean output and a warning if it changed anything.

| Stage | What it does |
|-------|-------------|
| Null bytes | Strip `\x00` |
| Invisibles | Strip zero-width, format/control, variation selectors, Unicode Tag block, bidi, C0/C1 |
| NFKC | Normalize fullwidth ASCII to standard ASCII |
| Homoglyphs | Replace Cyrillic/Greek/Armenian/Cherokee/typographic lookalikes with Latin equivalents |
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

> **Security note:** The escaper runs as the final pipeline stage.
> Its output is **not** re-sanitized. Built-in escapers are tested.
> Custom escapers are your responsibility — a buggy escaper can
> re-introduce characters the pipeline removed.

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

See [examples/](examples/) for runnable scripts covering LLM pipelines, FastAPI/Pydantic, and log sanitization.

## Walk untrusted data structures

```python
from navi_sanitize import walk

# Recursively sanitize every string in a dict/list
spec = walk(untrusted_json)
```

`walk()` warns when nesting exceeds 128 levels by default; pass `max_depth=` to adjust. Traverses dicts and lists only — tuples and sets pass through by reference.

## Opt-in Utilities

**These utilities are not part of `clean()` and are never run automatically.** You must call them explicitly.

```python
from navi_sanitize import decode_evasion, clean, detect_scripts, is_mixed_script, path_escaper

# Double-encoded path traversal
raw = "%252e%252e%252fetc%252fpasswd"

# 1. Peel nested encodings (URL → HTML entities → hex escapes)
peeled = decode_evasion(raw)           # "../../etc/passwd"

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

The pipeline never errors on valid string input. It always produces output. Non-string arguments raise `TypeError`. When it changes something, it logs a warning.

```python
import logging
logging.basicConfig()

clean("pаypal.com")
# WARNING:navi_sanitize:Replaced 1 homoglyph(s) in value
# Returns: "paypal.com"
```

## Performance

Measured on Python 3.13, single thread, AMD Ryzen 9 9950X. `clean()` is the per-string cost; `walk()` includes the iterative copy pass. Numbers are representative — expect ±20% on different hardware; CI runners are typically 2–3x slower.

| Scenario | Mean | Ops/sec |
|----------|------|---------|
| `clean()` — short, clean text (no-op) | 1.1 µs | 905K |
| `clean()` — short, hostile (all stages fire) | 21 µs | 48K |
| `clean()` — 13KB clean text | 292 µs | 3.4K |
| `clean()` — 10KB hostile text | 305 µs | 3.3K |
| `clean()` — 100KB hostile payload | 3.5 ms | 286 |
| `walk()` — 100-item nested dict, clean | 311 µs | 3.2K |
| `walk()` — 100-item nested dict, hostile | 2.5 ms | 408 |

## License

MIT
