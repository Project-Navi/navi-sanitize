# Pipeline Architecture

Every string passed to `clean()` flows through six stages in strict order. Each stage is a deterministic function that returns the cleaned string and a change indicator (a count for stages that strip or replace, a boolean for normalization). The pipeline orchestrator logs warnings when stages modify input.

## Data Flow

```
Input string
    │
    ▼
┌─────────────────────┐
│ 1. Null Byte Strip  │  \x00 → removed
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ 2. Invisible Strip  │  zero-width, tags, bidi → removed
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ 3. NFKC Normalize   │  fullwidth/compat → standard
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ 4. Homoglyph Replace│  Cyrillic/Greek → Latin
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ 5. Re-NFKC          │  re-normalize if homoglyphs changed
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ 6. Escaper (opt.)   │  context-specific escaping
└─────────┬───────────┘
          │
          ▼
    Output string
```

---

## Stage 1: Null Byte Removal

**What:** Strips all `\x00` bytes from the string.

**Why:** Null bytes cause C-extension string truncation. A string like `"admin\x00.jpg"` may be treated as `"admin"` by C code while Python sees the full string. This mismatch enables file extension spoofing and filter bypasses.

**Implementation:** `str.replace("\x00", "")` with a count of removed bytes.

**Example:**
```
"file\x00.txt"       → "file.txt"         (1 null byte removed)
"test\x00.json\x00"  → "test.json"        (2 null bytes removed)
```

---

## Stage 2: Invisible Character Stripping

**What:** Removes 492 invisible or near-invisible Unicode characters across 9 categories using a single compiled regex.

**Why:** Invisible characters are the most common evasion vector. They can:
- Break word boundaries without visible change (`"adm\u200bin"` looks like `"admin"`)
- Hide content from humans while remaining in the byte stream
- Encode invisible ASCII via the Unicode Tag block (tag smuggling)
- Reorder displayed text via bidirectional overrides

**Categories:**

| Category | Count | Range | Purpose |
|----------|-------|-------|---------|
| Zero-width | 8 | Individual chars | Hidden joiners, marks, word joiner, BOM |
| Format/control | 27 | Individual chars | Soft hyphen, thin/hair space, line/paragraph separators, annotation chars, math invisible operators, deprecated format controls, braille blank, ogham space, hangul fillers, Arabic letter mark |
| Variation selectors | 16 | U+FE00--U+FE0F | VS1--VS16, glyph presentation modifiers |
| Mongolian FVS | 4 | Individual chars | Free variation selectors (U+180B--U+180D, U+180F) |
| Tag block | 128 | U+E0000--U+E007F | Invisible ASCII encoding (tag smuggling) |
| Variation selector supplement | 240 | U+E0100--U+E01EF | VS17--VS256, extended glyph modifiers |
| Bidi controls | 9 | Individual chars | Directional overrides, embeddings, isolates |
| C0 controls | 28 | U+0001--U+001F | Terminal injection (BS, ESC, BEL); excludes TAB/LF/CR |
| C1 controls | 32 | U+0080--U+009F | CSI (equivalent to ESC+[), NEL, invisible in all contexts |

See [Character Reference](../reference/character-reference.md) for the complete table.

**Example:**
```
"te\u200bst"     → "test"     (1 zero-width space)
"a\u200b\u200c"  → "a"        (2 zero-width chars)
```

---

## Stage 3: NFKC Normalization

**What:** Applies Unicode NFKC (Compatibility Decomposition followed by Canonical Composition) normalization via `unicodedata.normalize("NFKC", s)`.

**Why:** NFKC collapses compatibility-equivalent characters to their standard forms. Without it, attackers can use fullwidth ASCII, superscripts, ligatures, and other compatibility forms to spell words that look different in bytes but render identically.

**What it normalizes:**
- **Fullwidth ASCII** --- `\uff41` (ａ) → `a`, `\uff21` (Ａ) → `A`
- **Ligatures** --- `ﬁ` → `fi`, `ﬀ` → `ff`
- **Superscripts/subscripts** --- `²` → `2`, `ⁿ` → `n`
- **Circled/parenthesized** --- `①` → `1`, `⒜` → `(a)`
- **Math italic/bold** --- `𝑎` → `a`, `𝐀` → `A`

**Why before homoglyphs:** NFKC can produce characters that are homoglyph targets. For example, some mathematical symbols normalize to Greek letters that then need homoglyph replacement. Running NFKC first ensures the homoglyph stage sees the canonical form.

**Example:**
```
"\uff41\uff44\uff4d\uff49\uff4e"  → "admin"     (fullwidth → ASCII)
"\U0001d44edmin"                   → "admin"     (math italic 𝑎 → a)
```

---

## Stage 4: Homoglyph Replacement

**What:** Replaces 66 visually confusable characters with their ASCII equivalents using a character-by-character scan against a lookup map. Decomposes to NFD first so that combining marks cannot hide mapped base characters.

**Why:** Homoglyphs are characters from different scripts that look identical to Latin letters. Cyrillic `а` (U+0430) is visually indistinguishable from Latin `a` (U+0061) in most fonts. Attackers exploit this for phishing (`pаypal.com`), filter bypasses, and identity spoofing.

**NFD decomposition:** Before scanning, the input is decomposed to NFD (Canonical Decomposition). This prevents combining marks from composing with homoglyph base characters under NFKC --- e.g., Cyrillic `а` + combining breve would compose to `ӑ` (not in the map), but NFD exposes the base `а` for replacement.

**Script coverage:**

| Script | Pairs | Example |
|--------|-------|---------|
| Cyrillic lowercase | 11 | а→a, е→e, о→o, р→p, с→c, у→y, х→x, і→i, ѕ→s, ј→j, һ→h |
| Cyrillic uppercase | 14 | А→A, В→B, Е→E, К→K, М→M, Н→H, О→O, Р→P, С→C, Т→T, Х→X, І→I, Ѕ→S, Ј→J |
| Cyrillic extended | 5 | Ӏ→I, ӏ→l, ԁ→d, ԛ→q, ԝ→w |
| Greek uppercase | 14 | Α→A, Β→B, Ε→E, Ζ→Z, Η→H, Ι→I, Κ→K, Μ→M, Ν→N, Ο→O, Ρ→P, Τ→T, Υ→Y, Χ→X |
| Greek lowercase | 11 | α→a, ι→i, ν→v, ο→o, ρ→p, μ→u, υ→u, κ→k, τ→t, γ→y, ω→w |
| Armenian | 2 | Օ→O, Ս→S |
| Cherokee | 1 | Ꭺ→A |
| Latin extended | 1 | ı→i |
| Typographic | 7 | −→-, –→-, —→-, '→', '→', "→", "→" |

See [Character Reference](../reference/character-reference.md) for the complete map with codepoints.

**Example:**
```
"pаypal.com"  → "paypal.com"  (Cyrillic а → Latin a)
"ΑΒC"         → "ABC"         (Greek Α,Β → Latin A,B)
"Ꭺdmin"       → "Admin"       (Cherokee Ꭺ → Latin A)
```

---

## Stage 5: Re-NFKC (Conditional)

**What:** Applies NFKC normalization a second time, but only if Stage 4 replaced any homoglyphs.

**Why:** Homoglyph replacement can produce Latin characters that combine with adjacent Unicode combining marks. For example, Greek `Υ` (U+03A5) followed by a combining tilde: Stage 4 replaces `Υ` with Latin `Y`, leaving `Y` + combining tilde, which NFKC composes into `Ỹ` (U+1EF8). Without re-normalization, `clean(clean(x))` could differ from `clean(x)` --- breaking idempotency.

**Key properties:**
- Only runs when Stage 4 actually replaced homoglyphs (zero cost for clean text)
- Ensures `clean(clean(x)) == clean(x)` for all inputs
- Does not produce a separate log message (the Stage 3 warning already covers NFKC)

---

## Stage 6: Escaper (Optional)

**What:** Applies a caller-supplied function (`str → str`) as the final transformation.

**Why:** The first five stages are universal --- they apply regardless of context. The escaper is context-specific: it depends on where the sanitized text will be used (template engine, filesystem, API, etc.).

**Key properties:**
- Runs **after** all universal stages
- Output is **not** re-sanitized (no infinite loops, no double-escaping)
- Must return `str` (raises `TypeError` otherwise)
- If `None`, the stage is skipped

**Built-in escapers:**
- `jinja2_escaper` --- escapes `{{ }}`, `{% %}`, `{# #}` template delimiters
- `path_escaper` --- strips `../`, `./`, leading `/`, embedded `..`

See [Writing Custom Escapers](../how-to/writing-custom-escapers.md) for how to build your own.

---

## Why Order Matters

The stage order is not arbitrary --- reordering breaks security guarantees.

**Null bytes before invisible chars:** Null bytes can split strings that, once joined, form invisible character sequences. Removing nulls first ensures the invisible stage sees the actual content.

**Invisibles before NFKC:** Some invisible characters are compatibility forms that NFKC would normalize rather than remove. Stripping them first is more aggressive and correct.

**NFKC before homoglyphs:** NFKC can produce characters that are homoglyph targets (e.g., mathematical symbols normalizing to Greek letters). Running normalization first ensures the homoglyph map catches everything.

**Re-NFKC after homoglyphs:** Homoglyph replacement can leave Latin characters adjacent to combining marks that NFKC would compose into precomposed forms. Running NFKC again ensures the output is fully normalized and `clean()` is idempotent.

**Homoglyphs before escaper:** The escaper operates on ASCII-normalized text. If homoglyphs remained, a Jinja2 escaper might miss `{{ cоnfig }}` (Cyrillic `о`) because the braces appear with a non-ASCII interior that doesn't match expected patterns.

**Escaper last:** The escaper's output is context-specific and should not be altered by earlier stages. Re-sanitizing escaper output could break its escaping (e.g., backslash-escaped braces being re-processed).

---

## Outside the Pipeline

navi-sanitize also provides opt-in utilities that are **not** pipeline stages. They are standalone functions composed by the caller.

**Default --- pipeline only:**

```
input → clean() → output
```

**Composed --- with opt-in utilities:**

```
input → decode_evasion() → clean() → (optional) detect_scripts() / is_mixed_script()
```

- **`decode_evasion()`** runs *before* `clean()` as a pre-processor. It peels nested URL/HTML/hex encodings that would otherwise pass through the pipeline unmodified.
- **`detect_scripts()` / `is_mixed_script()`** run on either raw or cleaned input as analysis tools. They return script information --- they never modify text.

These functions are never called by `clean()` or `walk()`. The caller decides when and whether to use them.
