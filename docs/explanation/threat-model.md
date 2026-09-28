# Threat Model

navi-sanitize is a deterministic text sanitization library. It removes and normalizes character-level tricks in untrusted input. This page documents what it covers, what it does not, and what it changes.

## Design Philosophy

1. **Deterministic** --- same input, same output. No ML models, no confidence scores, no thresholds.
2. **Narrow, predictable changes** --- CJK, Arabic, Hebrew, emoji and most other text pass through, but some legitimate text is changed; see [What Changes Legitimate Text](#what-changes-legitimate-text).
3. **Returns output for any string** --- `clean()`, `walk()` and `decode_evasion()` do not raise on string content, including lone surrogates. Non-`str` arguments to `clean()` and `decode_evasion()` raise `TypeError` (`walk()` returns non-container objects unchanged), `walk(max_depth=-1)` raises `ValueError`, and a custom escaper's own exceptions propagate.
4. **Pluggable** --- the universal pipeline handles character-level vectors; escapers handle one destination each.

## Covered Threats

### Null Byte Injection
**Vector:** `\x00` in strings can truncate processing in C extensions and other languages.
**Example:** `"admin\x00.jpg"` → file extension spoofing, filter bypass.
**Mitigation:** All null bytes are stripped (Stage 1).

### Invisible Character Attacks
**Vector:** 492 invisible, formatting and control characters.
**Examples:**
- Zero-width spaces splitting words: `"adm\u200bin"` looks like `"admin"`
- Tag-block characters carrying invisible ASCII (tag smuggling)
- Bidi overrides reordering displayed text
- C0/C1 controls such as ESC that drive terminal escape sequences
**Mitigation:** One compiled regex strips the whole set (Stage 2).

### Fullwidth/Compatibility Encoding Bypass
**Vector:** Compatibility forms spell ASCII words with other code points.
**Example:** `"\uff41\uff44\uff4d\uff49\uff4e"` renders as `"admin"` but does not equal it.
**Mitigation:** NFKC normalization (Stage 3).

### Homoglyph Substitution
**Vector:** Letters from other scripts that look like Latin letters.
**Examples:**
- `"pаypal.com"` --- Cyrillic `а` (U+0430)
- `"Ꭺdmin"` --- Cherokee `Ꭺ` (U+13AA)
- `"−100"` --- minus sign `−` (U+2212)
**Mitigation:** A curated 66-pair map (Stage 4), applied after NFD decomposition so combining marks cannot hide a mapped base letter. Confusables outside the map are not replaced.

### Jinja2 Template Injection (SSTI)
**Vector:** Untrusted text that becomes part of Jinja2 template *source* can open `{{ }}`, `{% %}` or `{# #}` tags.
**Example:** `"{{ config.__class__.__init__.__globals__ }}"`.
**Mitigation:** The safe design is to keep template source trusted and pass untrusted values as render context; Jinja2 does not evaluate context values. Where text must be embedded in source, `jinja2_escaper` (Stage 6) backslash-escapes every character of the default delimiters, including brace runs and overlapping sequences such as `{{%`. It does not handle custom delimiter settings, escape HTML or sandbox the template.

### Path Traversal
**Vector:** `../`, leading `/` and backslash sequences in a path fragment.
**Example:** `"../../../etc/passwd"`.
**Mitigation:** `path_escaper` (Stage 6) converts backslashes to `/` and removes leading slashes, empty, `.` and `..` segments, and embedded `..`. It is lexical: it does not confine the result to a directory, resolve symlinks, reject drive-qualified paths such as `C:/temp`, or check the filesystem, and the result may be empty. Join the result to a base directory and verify containment (for example with `Path.resolve()` and `is_relative_to()`) before using it.

### Compound Attacks
**Examples:**
- `"{{ cоnfig }}"` --- Jinja2 delimiters plus a Cyrillic homoglyph
- `"n\u0430vi\x00"` --- homoglyph plus null byte
- `"../\x00../../etc/passwd"` --- traversal split by a null byte
**Mitigation:** Each universal stage removes its category before the next runs, so the escaper sees normalized text.

### Multi-Encoding Evasion (opt-in)
**Vector:** Nested URL, HTML entity and `\xHH` encodings (`%252e%252e%252f`, `&amp;lt;`) that single-layer decoders miss.
**Example:** `"%252e%252e%252fetc%252fpasswd"` decodes to `"../etc/passwd"` in two passes.
**Mitigation:** `decode_evasion()` runs URL → HTML entity → hex decoding per pass, up to `max_layers` passes (default 3). Invalid percent bytes stay as `%XX` text. Compose it yourself: `clean(decode_evasion(raw), escaper=path_escaper)`.

### Mixed-Script Detection (opt-in)
**Signal:** `detect_scripts()` and `is_mixed_script()` report when text mixes script buckets (Latin, Cyrillic, Greek, Arabic, Hebrew, Armenian, Cherokee, CJK), a common sign of homoglyph spoofing. They do not modify text, and scripts outside those buckets are ignored. Use them on **raw** input; `clean()` removes the signal.

## What Changes Legitimate Text

These are intended consequences of the character policy. Decide per field whether they are acceptable.

- **Mapped letters inside real words.** `clean("привет")` returns `'пpивeт'`: the Cyrillic `р` and `е` become Latin, producing mixed-script text.
- **Typography.** Curly quotes, en/em dashes and the minus sign become ASCII.
- **Emoji sequences.** ZWJ (U+200D) is stripped, so family and profession emoji split into their parts; variation selectors (such as U+FE0F after `❤`) and tag sequences in subdivision flags are removed.
- **Right-to-left text.** Arabic letter mark (U+061C), LRM/RLM (U+200E/U+200F) and the bidi embedding, override and isolate controls are removed; rendering may need directional marks re-added downstream.
- **Spacing and line breaks.** Thin and hair spaces, the soft hyphen, U+2028/U+2029 and NEL are deleted, not replaced: `clean("10\u2009000")` returns `'10000'` and two lines joined by U+2028 run together.
- **Mongolian.** Free variation selectors (U+180B--U+180D, U+180F) are removed.
- **Compatibility forms.** NFKC folds ligatures, superscripts, circled and fullwidth forms (`ﬁ` → `fi`, `²` → `2`); combined with the homoglyph map, the micro sign turns into `u` (`clean("5µm")` returns `'5um'`).

## Not Covered

### HTML/XML Escaping
Use your template engine's auto-escaping (`markupsafe.escape()`, Jinja2 `autoescape=True`, Django templates). HTML escaping depends on context (attributes, scripts, CSS).

### SQL Injection
Use parameterized queries.

### Encodings `decode_evasion()` does not handle
Only URL percent-encoding, HTML entities and `\xHH` escapes are decoded, and only when you call it. Base64 and other formats are deliberately not decoded: arbitrary tokens, keys and binary data are often valid base64, and guessing would corrupt them. Decoding also changes meaning, which is why it is opt-in.

### LLM Prompt Injection
Instructions written in ordinary text are unaffected by character sanitization. The pluggable escaper can protect prompt delimiters you define (see [Writing Custom Escapers](../how-to/writing-custom-escapers.md)), but model-side defenses, least-privilege tools and review are still needed.

### Encoding Beyond Unicode
navi-sanitize operates on Python `str`. Decode bytes and legacy encodings (Shift-JIS, ISO-8859-1) to `str` first.

### Characters NFKC Creates
NFKC turns some code points into security-sensitive ASCII: fullwidth `＜`/`＞` become `<`/`>`, fullwidth quotes become `"`/`'`, and the Greek question mark (U+037E) becomes `;`. That is the point of normalizing, but the result may need escaping for its destination. The built-in escapers run after NFKC, so NFKC-produced braces, dots and slashes are handled for their own destinations; provide an escaper for anything else.

### Latin Lookalikes Within Latin
Small capitals (`ᴀᴅᴍɪɴ`, U+1D00--U+1D22) and IPA letters such as `ɑ` (U+0251) are Latin script and not mapped. Use application-level allowlists for high-risk identifiers such as usernames.

### Dictionary Key Identity
`walk()` sanitizes keys. Distinct keys that sanitize (or escape) to the same string collide: the last value is kept and a warning with the collision count is logged. Where distinct keys must be preserved, validate before or after sanitizing.

### Resource Limits
`walk(max_depth=...)` is an advisory warning threshold, not a limit. It warns once when a container is first reached at depth ≥ `max_depth` (the top-level container is depth 0) and keeps going; a container shared by several paths is measured where it is first reached. Bound input size and nesting where you parse it.

### Regex Escaping
Use `re.escape()`.

## Attack Vector Examples

| Attack | Input | Output | Stages |
|--------|-------|--------|--------|
| Phishing domain | `pаypal.com` | `paypal.com` | Homoglyphs |
| Zero-width evasion | `te\u200bst` | `test` | Invisibles |
| Null truncation | `admin\x00.jpg` | `admin.jpg` | Null bytes |
| Fullwidth bypass | `ａｄｍｉｎ` | `admin` | NFKC |
| SSTI in template source | `{{ config }}` | `\{\{ config \}\}` | Escaper (jinja2) |
| Path traversal | `../../../etc/passwd` | `etc/passwd` | Escaper (path) |
| Tag smuggling | `\U000e0061\U000e0064\U000e006d\U000e0069\U000e006e` | *(empty)* | Invisibles |
| Bidi override | `\u202eSSTI{{ x }}` | `SSTI\{\{ x \}\}` | Invisibles + Escaper |
| Homoglyph + SSTI | `{{ cоnfig }}` | `\{\{ config \}\}` | Homoglyphs + Escaper |
| Null + traversal | `../\x00../../passwd` | `passwd` | Null bytes + Escaper (path) |
