# Comparison with Other Tools

navi-sanitize combines invisible-character stripping, NFKC normalization, a small homoglyph map and a pluggable escaper in one dependency-free call. Other libraries solve neighboring problems, and several compose with it. This page describes each tool's design goal; check each project's own documentation for its current behavior.

## At a Glance

| Tool | Designed for | Relationship to navi-sanitize |
|------|--------------|-------------------------------|
| Unidecode / anyascii | Transliterating text to ASCII | Different goal: they rewrite all non-ASCII text |
| confusable_homoglyphs | Detecting confusables from Unicode's confusables data | Detection over a far larger dataset; navi-sanitize replaces a small set |
| ftfy | Repairing mojibake and encoding damage | Complementary: repair first, then sanitize |
| MarkupSafe / nh3 | Escaping or sanitizing HTML | Complementary: sanitize characters, then handle HTML |
| pydantic / cerberus | Schema validation | Call `clean()` from a validator |
| python-slugify | URL slugs | Different goal: ASCII slugs, not sanitized text |

## Details

### Unidecode / anyascii

Transliteration maps every non-ASCII character to an ASCII approximation, which suits slugs and search keys but rewrites all non-Latin text. navi-sanitize leaves characters outside its lists alone (for example CJK, most Arabic and Hebrew, and single emoji) and replaces only its 66 mapped lookalikes, which still changes some legitimate text; see the [threat model](threat-model.md#what-changes-legitimate-text).

### confusable_homoglyphs

Reports confusable characters using the Unicode Consortium's `confusables.txt` data. It detects rather than replaces and covers many more pairs. navi-sanitize's map is small by design; `is_mixed_script()` is its detection-style signal.

### ftfy

Repairs text decoded with the wrong encoding and similar damage, and tries to keep characters an author may have intended, so it is not a replacement for stripping invisible characters. Run it first:

```python
import ftfy
from navi_sanitize import clean

text = clean(ftfy.fix_text(raw_input))
```

### MarkupSafe / nh3

These escape HTML (MarkupSafe) or sanitize HTML markup (nh3). navi-sanitize works on the characters inside that markup, so the two compose:

```python
from markupsafe import escape
from navi_sanitize import clean

safe_html = escape(clean(user_input))
```

### pydantic / cerberus

Validation frameworks check types, lengths and patterns; they do not strip invisible characters or map homoglyphs. Call `clean()` from a validator:

```python
from typing import Annotated
from pydantic import AfterValidator, BaseModel
from navi_sanitize import clean

SanitizedStr = Annotated[str, AfterValidator(clean)]

class UserInput(BaseModel):
    name: SanitizedStr
    bio: SanitizedStr
```

### python-slugify

Produces URL-safe ASCII slugs by transliterating, lowercasing and dropping punctuation. Use it for slugs, not for preserving user text.

## What navi-sanitize Does Not Replace

- **HTML sanitizers** (nh3, DOMPurify) for tag and attribute filtering
- **SQL parameterization**
- **URL validation** with a real URL parser
- **Encoding repair** (ftfy)
- **Full transliteration** (Unidecode, anyascii) when you need ASCII-only output

## Design Choices

### Curated homoglyph map

Unicode's confusables data lists thousands of pairs across many scripts. navi-sanitize maps 66: Cyrillic, Greek, Armenian, Cherokee and Latin Extended letters that look like Latin letters in common fonts, plus typographic quotes and dashes. A small map keeps changes predictable but leaves other confusables in place.

### Replace instead of detect

Detection APIs leave the decision to the application. navi-sanitize replaces mapped characters and strips invisible ones, so downstream code sees normalized text; applications that need to know whether text was altered can compare input and output, check the log counts, or call `is_mixed_script()` on the raw input.

### Zero dependencies

Only the standard library is used at runtime, so there are no third-party runtime packages to install, audit or pin, and it runs wherever CPython 3.12+ does.
