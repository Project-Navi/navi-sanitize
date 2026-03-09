# Comparison with Other Tools

navi-sanitize is the only library that combines invisible character stripping, homoglyph replacement, NFKC normalization, and pluggable escaping in a single zero-dependency pipeline. This page explains how it relates to existing tools.

## Overview

| | navi-sanitize | Unidecode / anyascii | confusable_homoglyphs | ftfy | MarkupSafe / nh3 | pydantic |
|---|---|---|---|---|---|---|
| **Purpose** | Security sanitization | ASCII transliteration | Homoglyph detection | Encoding repair | HTML escaping | Schema validation |
| **Invisible chars** | Strips 492 (bidi, tag block, ZW, VS, C0/C1) | Incidental | No | Partial (preserves bidi, ZW, VS) | No | No |
| **Homoglyphs** | Replaces 66 curated pairs | Transliterates all non-ASCII | Detects only | No | No | No |
| **NFKC** | Yes | No | No | NFC (NFKC optional) | No | No |
| **Null bytes** | Yes | No | No | No | No | No |
| **Preserves Unicode** | Yes | No | Yes | Yes | Yes | Yes |
| **Pluggable escaper** | Yes | No | No | No | N/A | N/A |
| **Dependencies** | Zero | Zero | Zero | wcwidth | C ext / Rust ext | Rust ext |

## Detailed Comparisons

### vs. Unidecode / anyascii

**What they do:** Transliterate *all* Unicode to ASCII via lookup tables. Every non-ASCII code point maps to an ASCII string.

**Why they're different:** Transliteration destroys content. Unidecode turns Chinese characters into pinyin, Cyrillic sentences into romanized gibberish, and Arabic into Latin approximations. It's designed for slug generation, not security.

navi-sanitize normalizes only the 66 highest-risk Latin lookalikes and leaves legitimate Unicode intact. CJK, Arabic, emoji, and non-confusable Cyrillic pass through unchanged.

| Input | navi-sanitize | Unidecode |
|-------|--------------|-----------|
| `pаypal.com` (Cyrillic а) | `paypal.com` | `paypal.com` |
| `"hello"` (smart quotes) | `"hello"` | `"hello"` |
| `안녕하세요` (Korean) | `안녕하세요` | `annyeonghaseyo` |
| `漢字` (CJK) | `漢字` | `Han Zi` |
| `hello 🎉` (emoji) | `hello 🎉` | `hello ` |

### vs. confusable_homoglyphs

**What it does:** Detects confusable characters using the Unicode Consortium's official `Confusables.txt` dataset. Returns analysis of which characters are confusable and from which scripts.

**Why it's different:** Detection-only API --- it tells you *what's* confusable but doesn't replace anything. You'd need to build your own replacement layer on top. The library is also archived upstream.

navi-sanitize's 66-pair map is intentionally curated for the highest-risk Latin lookalikes (Cyrillic, Greek, Armenian, Cherokee, Latin Extended, and typographic) rather than the full Unicode confusables set. This keeps the pipeline fast and avoids false positives from low-risk script pairs.

### vs. ftfy

**What it does:** Fixes encoding corruption (mojibake), HTML entities in wrong contexts, curly-quote issues, and C1 control characters. Applies NFC normalization by default.

**Why it's different:** ftfy and navi-sanitize solve different problems. ftfy repairs *accidental* encoding damage; navi-sanitize strips *intentional* evasion vectors.

Critically, ftfy explicitly **preserves** bidi overrides (U+202A-U+202E), zero-width characters (U+200B-U+200D), variation selectors, and Tag block characters. Its design philosophy is "don't remove characters that might be intentional." navi-sanitize's design philosophy is "remove characters that can be weaponized."

**They compose well:** Run ftfy first to fix mojibake, then navi-sanitize to strip evasion vectors.

```python
import ftfy
from navi_sanitize import clean

text = ftfy.fix_text(raw_input)   # Fix encoding corruption
text = clean(text)                 # Strip evasion vectors
```

### vs. MarkupSafe / nh3 / bleach

**What they do:** HTML escaping (MarkupSafe) and HTML tag/attribute sanitization (nh3, bleach).

**Why they're different:** These operate at the HTML *structure* layer --- escaping `<`, `>`, `&` and stripping dangerous tags/attributes. navi-sanitize operates at the *character content* layer --- normalizing the text inside those HTML elements.

They address orthogonal attack surfaces and compose naturally:

```python
from markupsafe import escape
from navi_sanitize import clean

# navi-sanitize normalizes characters, MarkupSafe escapes HTML
safe_html = escape(clean(user_input))
```

Note: bleach is deprecated (html5lib dependency unmaintained). Use nh3 for HTML sanitization.

### vs. pydantic / cerberus

**What they do:** Schema validation and data coercion for Python data structures.

**Why they're different:** Validation frameworks check *format constraints* (types, lengths, patterns) but don't sanitize character-level content. Pydantic's `strip_whitespace` strips leading/trailing whitespace but doesn't touch invisible Unicode, homoglyphs, or null bytes.

navi-sanitize is designed to plug into these frameworks:

```python
from typing import Annotated
from pydantic import AfterValidator, BaseModel
from navi_sanitize import clean

SanitizedStr = Annotated[str, AfterValidator(clean)]

class UserInput(BaseModel):
    name: SanitizedStr
    bio: SanitizedStr
```

### vs. python-slugify

**What it does:** Converts Unicode text to URL-safe ASCII slugs via transliteration, lowercasing, and non-alphanumeric stripping.

**Why it's different:** Destructive by design --- produces ASCII slugs, not sanitized original text. Its purpose is URL generation, not security sanitization. Also depends on text-unidecode.

## What navi-sanitize Does Not Replace

- **HTML sanitizers** (nh3, DOMPurify) --- use these for HTML tag/attribute filtering
- **SQL parameterization** --- use prepared statements, not string escaping
- **URL validation** --- use `validators` or framework URL parsing
- **Encoding repair** --- use ftfy for mojibake and encoding corruption
- **Full transliteration** --- use Unidecode/anyascii when you need ASCII-only output

## Design Choices

### Curated homoglyph map vs. full Unicode confusables

The Unicode Consortium's `Confusables.txt` contains thousands of pairs across many scripts. navi-sanitize uses a curated 66-pair subset focused on:

1. **Highest visual similarity** --- characters that are pixel-identical in common fonts
2. **Most commonly weaponized** --- Cyrillic/Greek-to-Latin pairs used in phishing and filter bypass
3. **Typographic normalization** --- smart quotes, em/en dashes, minus signs

This preserves legitimate Unicode while covering the attack surface that matters in practice.

### Strip vs. detect

Libraries like confusable_homoglyphs provide detection APIs that return analysis of *what's* confusable. This is useful for research and alerting but requires application code to decide what to do.

navi-sanitize takes an opinionated approach: confusable characters are replaced, invisible characters are stripped, and the pipeline always produces clean output. The application never needs to handle "this input might be dangerous" --- it's already been fixed.

### Zero dependencies

navi-sanitize uses only the Python standard library. This means:

- No supply chain risk from transitive dependencies
- No C extensions to compile (pure Python, runs anywhere CPython does)
- No version conflicts with other packages
- Trivial to vendor into locked-down environments
