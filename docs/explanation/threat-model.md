# Threat Model

navi-sanitize is a deterministic text sanitization library. It transforms untrusted input into safe output while preserving legitimate Unicode by design. This page documents what it covers, what it doesn't, and why.

## Design Philosophy

1. **Deterministic** --- same input, same output, every time. No ML models, no heuristics, no confidence scores.
2. **Legitimate Unicode preserved** --- CJK, Arabic, Hebrew, emoji, and non-confusable text pass through unchanged. A string that passes through unmodified was already clean.
3. **Always returns output** --- never throws on bad input (except `TypeError` for non-strings). Attackers can't cause denial of service by crafting inputs that error.
4. **Pluggable** --- the universal pipeline handles common vectors; escapers handle context-specific threats.

## Covered Threats

### Null Byte Injection
**Vector:** `\x00` bytes in strings cause C-extension truncation.
**Example:** `"admin\x00.jpg"` → file extension spoofing, filter bypass.
**Mitigation:** All null bytes are stripped (Stage 1).

### Invisible Character Attacks
**Vector:** 492 invisible Unicode characters hidden in text.
**Examples:**
- Zero-width spaces breaking word boundaries: `"adm\u200bin"` looks like `"admin"`
- Tag block encoding invisible ASCII (tag smuggling attacks)
- Bidi overrides reordering displayed text to hide malicious content
**Mitigation:** Single compiled regex strips all invisible characters (Stage 2).

### Fullwidth/Compatibility Encoding Bypass
**Vector:** Unicode compatibility forms spell ASCII words with non-ASCII bytes.
**Example:** `"\uff41\uff44\uff4d\uff49\uff4e"` renders as `"admin"` but bypasses ASCII filters.
**Mitigation:** NFKC normalization collapses compatibility forms (Stage 3).

### Homoglyph Substitution
**Vector:** Characters from other scripts look identical to Latin letters.
**Examples:**
- `"pаypal.com"` --- Cyrillic `а` (U+0430) looks like Latin `a` (U+0061)
- `"Ꭺdmin"` --- Cherokee `Ꭺ` (U+13AA) looks like Latin `A`
- `"−100"` --- minus sign `−` (U+2212) looks like hyphen `-`
**Mitigation:** 66-pair replacement map covering Cyrillic, Greek, Armenian, Cherokee, Latin Extended, and typographic confusables (Stage 4). NFD decomposition before scanning prevents combining marks from hiding mapped base characters.

### Jinja2 Template Injection (SSTI)
**Vector:** `{{ }}`, `{% %}`, `{#  #}` delimiters in user input execute server-side code.
**Example:** `"{{ config.__class__.__init__.__globals__ }}"` dumps server state.
**Mitigation:** `jinja2_escaper` backslash-escapes all template delimiters (Stage 6).

### Path Traversal
**Vector:** `../`, leading `/`, backslash sequences access files outside intended directory.
**Example:** `"../../../etc/passwd"` escapes the upload directory.
**Mitigation:** `path_escaper` strips traversal sequences and normalizes separators (Stage 6).

### Compound/Mixed Attacks
**Vector:** Combining multiple vectors to bypass single-layer defenses.
**Examples:**
- `"{{ cоnfig }}"` --- Jinja2 delimiters + Cyrillic homoglyph
- `"n\u0430vi\x00"` --- homoglyph + null byte
- `"../\x00../../etc/passwd"` --- path traversal + null byte concatenation
**Mitigation:** All universal stages run in sequence, each removing its category before the next stage processes the result. Compound attacks are disarmed layer by layer.

### Multi-Encoding Evasion (opt-in)
**Vector:** Attackers nest URL, HTML entity, and hex encodings (`%252e%252e%252f`, `&amp;lt;script&amp;gt;`) to sneak payloads past single-layer decoders.
**Example:** `"%252e%252e%252fetc%252fpasswd"` → double-encoded path traversal.
**Mitigation:** `decode_evasion()` iteratively peels encoding layers (URL → HTML entity → hex per pass) until a pass produces no change. Compose with `clean()`: `clean(decode_evasion(raw), escaper=path_escaper)`.
**Note:** Opt-in --- not part of the default pipeline. See [API Reference](../reference/api.md) for details.

### Mixed-Script Detection (opt-in)
**Vector:** Homoglyph-based phishing uses characters from multiple scripts (e.g., Cyrillic `а` mixed with Latin) to create visually identical but distinct strings.
**Signal:** `detect_scripts()` and `is_mixed_script()` identify when text contains characters from 2+ scripts, which is a strong indicator of homoglyph spoofing. These are analysis tools --- they return information but do not modify text.
**Note:** Most useful on **raw** input before `clean()`, since homoglyph replacement normalizes the mixed-script signal away.

## Not Covered

navi-sanitize intentionally does **not** cover these categories:

### HTML/XML Escaping
Use your template engine's auto-escaping (`markupsafe.escape()`, Jinja2 `autoescape=True`, Django templates). HTML escaping is context-dependent (attributes, script tags, CSS) and well-served by existing tools.

### SQL Injection
Use parameterized queries / prepared statements. SQL injection is a query-construction problem, not a text-sanitization problem.

### URL Decoding / Encoding
Multi-encoding evasion (nested URL, HTML entity, and hex encodings) is now available via the **opt-in** `decode_evasion()` pre-processor. It is opt-in because decoding can change semantics and surprise callers who expect percent-encoded strings to remain intact. `decode_evasion()` is not part of `clean()` --- you must call it explicitly before the pipeline.

**Base64 decoding is intentionally excluded in v1** to avoid false positives from decoding opaque blobs (API keys, encrypted tokens, binary data) that happen to be valid base64.

### LLM Prompt Injection
Vendor prompt syntax moves too fast for a static library. The pluggable escaper design lets you write context-specific prompt escapers. See [Writing Custom Escapers](../how-to/writing-custom-escapers.md) for a skeleton.

### Encoding Beyond Unicode
navi-sanitize operates on Python `str` (Unicode). It does not handle raw byte streams, legacy encodings (Shift-JIS, ISO-8859-1), or binary data. Decode to `str` first.

### NFKC Normalization Creates Injection-Sensitive Characters

NFKC normalization (Stage 3) converts certain Unicode codepoints to security-sensitive ASCII:
fullwidth angle brackets (U+FF1C/U+FF1E) become `<`/`>`, fullwidth quotes (U+FF02/U+FF07)
become `"`/`'`, and Greek question mark (U+037E) becomes `;`. These conversions are correct
for security normalization --- they prevent bypass via Unicode variants --- but the resulting
characters can enable injection in HTML, shell, or SQL contexts.

**The built-in escapers handle their own domains:** `jinja2_escaper` catches all NFKC-produced
brace combinations; `path_escaper` catches all NFKC-produced dot/slash combinations. For other
contexts, provide an appropriate escaper. See [Writing Custom Escapers](../how-to/writing-custom-escapers.md) for examples including
`html.escape()` and `shlex.quote()` wrappers.

### Stripping Arabic Letter Mark and Mongolian FVS

Arabic letter mark (U+061C) is stripped because it is invisible and can hide content from
pattern-matching tools. However, it is legitimately used in RTL text to influence word joining
behavior. Similarly, Mongolian Free Variation Selectors (U+180B--U+180D, U+180F) are stripped
because they are invisible glyph modifiers exploitable for evasion, but they are used in
legitimate Mongolian script rendering.

**Impact:** Applications processing Arabic or Mongolian text may lose rendering hints. If your
application requires these characters, apply `clean()` selectively (e.g., sanitize user-facing
fields but not body text known to contain these scripts), or write a custom post-processor that
re-inserts them from a trusted source.

### Latin Small Capitals and IPA Characters Are Not Mapped

Characters like ᴀᴅᴍɪɴ (Latin Small Capitals, U+1D00--U+1D22) and ɑ (Latin Small Letter Alpha,
U+0251) are visually similar to standard Latin letters but are classified as Latin script by
Unicode. The homoglyph map targets cross-script confusables (Cyrillic, Greek, Armenian, Cherokee)
where the script mismatch is the attack signal. Latin-to-Latin visual similarity is a different
threat model better served by `detect_scripts()` and `is_mixed_script()` --- or by application-level
character allowlisting for high-security contexts like username registration.

### Regex Escaping
Use `re.escape()`. Regex metacharacter escaping is context-specific and already solved by the stdlib.

## Attack Vector Examples

| Attack | Input | Output | Stages Fired |
|--------|-------|--------|-------------|
| Phishing domain | `pаypal.com` | `paypal.com` | Homoglyphs |
| Zero-width evasion | `te\u200bst` | `test` | Invisibles |
| Null truncation | `admin\x00.jpg` | `admin.jpg` | Null bytes |
| Fullwidth bypass | `ａｄｍｉｎ` | `admin` | NFKC |
| SSTI attempt | `{{ config }}` | `\{\{ config \}\}` | Escaper (jinja2) |
| Path traversal | `../../../etc/passwd` | `etc/passwd` | Escaper (path) |
| Tag smuggling | `\U000e0061\U000e0064\U000e006d\U000e0069\U000e006e` | *(empty)* | Invisibles |
| Bidi override | `\u202eSSTI{{ x }}` | `SSTI\{\{ x \}\}` | Invisibles + Escaper |
| Mixed: homoglyph + SSTI | `{{ cоnfig }}` | `\{\{ config \}\}` | Homoglyphs + Escaper |
| Mixed: null + traversal | `../\x00../../passwd` | `passwd` | Null bytes + Escaper (path) |
