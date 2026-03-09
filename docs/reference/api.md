# API Reference

All public symbols are exported from `navi_sanitize`:

```python
from navi_sanitize import (
    clean, walk, jinja2_escaper, path_escaper, Escaper,
    decode_evasion, detect_scripts, is_mixed_script,
)
```

---

## `clean(text, *, escaper=None)`

Sanitize a single string through the universal pipeline.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | *(required)* | The string to sanitize |
| `escaper` | `Escaper \| None` | `None` | Optional escaper function applied as the final stage |

**Returns:** `str` --- the sanitized string.

**Raises:** `TypeError` --- if `text` is not a `str`, or if the escaper returns a non-`str`.

**Stages (in order):**
1. Null byte removal
2. Invisible character stripping
3. NFKC normalization
4. Homoglyph replacement
5. Re-NFKC (if homoglyphs were replaced --- ensures idempotency)
6. Escaper (if provided)

Always returns output. Logs warnings when input is modified.

**Examples:**

```python
from navi_sanitize import clean, jinja2_escaper

# No-op for clean text
clean("hello world")  # "hello world"

# All stages fire
clean("n\u0430vi\x00\u200b")  # "navi"

# With escaper
clean("{{ config }}", escaper=jinja2_escaper)  # "\\{\\{ config \\}\\}"

# TypeError on non-string
clean(42)  # TypeError: clean() requires str, got int
```

---

## `walk(data, *, escaper=None)`

Recursively sanitize every string in a dict/list/nested structure.

Uses PEP 695 generic syntax: `def walk[T](data: T, *, escaper=None) -> T`

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | `T` | *(required)* | Any Python object; strings within dicts/lists are sanitized |
| `escaper` | `Escaper \| None` | `None` | Optional escaper function applied to each string |

**Returns:** `T` --- a deep copy of the input with all strings sanitized.

**Behavior by type:**

| Type | Behavior |
|------|----------|
| `str` | Passed through `clean()` |
| `dict` | Both keys and values sanitized recursively |
| `list` | Elements sanitized recursively |
| `tuple`, `set`, `bytes`, `int`, `float`, `bool`, `None` | Passed through unchanged |

The original data is **never modified** --- `walk()` operates on a `deepcopy`.

**Examples:**

```python
from navi_sanitize import walk

# Nested structure
result = walk({
    "user": "pаypal",       # Cyrillic а → Latin a
    "tags": ["te\u200bst"], # zero-width space removed
    "count": 42             # int passes through
})
# {"user": "paypal", "tags": ["test"], "count": 42}

# Dict keys are also sanitized
walk({"\u0430dmin": "value"})  # {"admin": "value"}

# Non-dict/list input
walk("he\x00llo")  # "hello"
walk(42)            # 42
```

---

## `Escaper`

Type alias for escaper functions.

```python
Escaper = Callable[[str], str]
```

Any function that accepts a `str` and returns a `str` can be used as an escaper. The escaper runs as the final pipeline stage, after all universal stages have completed. The escaper's output is **not** re-sanitized.

---

## `jinja2_escaper(text)`

Escape Jinja2 template delimiters in a string.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `text` | `str` | The string to escape |

**Returns:** `str` --- the string with Jinja2 delimiters backslash-escaped.

**What it escapes:**
- `{{` and `}}` --- expression delimiters
- `{%` and `%}` --- statement delimiters
- `{#` and `#}` --- comment delimiters
- Runs of 2+ braces (`{{{`, `}}}`) --- handles triple-brace edge cases

Uses a single-pass regex: `\{{2,}|\}{2,}|\{%|%\}|\{#|#\}`

Each character in a matched delimiter is individually backslash-escaped.

**Examples:**

```python
from navi_sanitize import jinja2_escaper

jinja2_escaper("{{ config }}")     # "\\{\\{ config \\}\\}"
jinja2_escaper("{% import os %}")  # "\\{\\% import os \\%\\}"
jinja2_escaper("{# comment #}")    # "\\{\\# comment \\#\\}"
jinja2_escaper("{{{ triple }}}")   # "\\{\\{\\{ triple \\}\\}\\}"
jinja2_escaper("no delimiters")    # "no delimiters"
```

---

## `path_escaper(text)`

Remove path traversal sequences from a string.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `text` | `str` | The path string to sanitize |

**Returns:** `str` --- the path with traversal sequences removed.

**Algorithm:**
1. Replace backslashes with forward slashes
2. Strip leading `/`
3. Split on `/`
4. Remove `..` and `.` segments
5. Remove embedded `..` within segments (handles null-byte concatenation artifacts)
6. Rejoin non-empty segments

**Examples:**

```python
from navi_sanitize import path_escaper

path_escaper("../../../etc/passwd")    # "etc/passwd"
path_escaper("/etc/passwd")            # "etc/passwd"
path_escaper("foo/../../../bar")       # "foo/bar"
path_escaper("..\\..\\windows\\cmd")   # "windows/cmd"
path_escaper("safe/path/file.txt")     # "safe/path/file.txt"
```

---

# Opt-in Utilities

**These functions are not part of `clean()` and are never run automatically.** They are standalone primitives you compose with the pipeline yourself.

---

## `decode_evasion(text, *, max_layers=3)`

Iteratively decode nested URL, HTML entity, and hex escape encodings from a string.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | *(required)* | The string to decode |
| `max_layers` | `int` | `3` | Maximum decoding passes before stopping |

**Returns:** `str` --- the decoded string.

**Behavior:**
- Runs URL decoding → HTML entity unescaping → hex escape decoding (`\xHH`) per pass
- A pass counts as one layer if the output differs from the input
- Stops when a pass produces no change or `max_layers` is reached
- `max_layers <= 0` is a no-op (returns `text` unchanged)
- Invalid or partial encodings do not raise --- they pass through unchanged
- Logs a warning with the layer count when decoding occurs; never includes decoded content in log messages

**Examples:**

```python
from navi_sanitize import decode_evasion, clean, path_escaper

# Single layer of URL encoding
decode_evasion("%2e%2e%2fetc%2fpasswd")       # "../etc/passwd"

# Double-encoded (two layers)
decode_evasion("%252e%252e%252fetc%252fpasswd")  # "../../etc/passwd"

# HTML entities
decode_evasion("&lt;script&gt;")              # "<script>"

# Hex escapes
decode_evasion("\\x41\\x42\\x43")             # "ABC"

# Compose with clean()
raw = "%252e%252e%252fetc%252fpasswd"
clean(decode_evasion(raw), escaper=path_escaper)  # "etc/passwd"

# No-op when max_layers <= 0
decode_evasion("%41", max_layers=0)            # "%41"
```

---

## `detect_scripts(text)`

Return the set of script buckets present in a string.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `text` | `str` | The string to analyze |

**Returns:** `set[str]` --- script bucket names found in the text.

**Buckets:**

| Bucket | Covers |
|--------|--------|
| `latin` | Latin script characters |
| `cyrillic` | Cyrillic script characters |
| `greek` | Greek script characters |
| `arabic` | Arabic script characters |
| `hebrew` | Hebrew script characters |
| `armenian` | Armenian script characters |
| `cherokee` | Cherokee script characters |
| `cjk` | CJK Unified, Hiragana, Katakana, and Hangul |

Only the listed buckets are returned. Characters whose Unicode name doesn't match any known prefix are silently ignored. Non-alphabetic characters (digits, punctuation, emoji) are skipped.

**Examples:**

```python
from navi_sanitize import detect_scripts

detect_scripts("hello world")   # {"latin"}
detect_scripts("Привет")        # {"cyrillic"}
detect_scripts("pаypal.com")   # {"latin", "cyrillic"} — Cyrillic а
detect_scripts("12345!@#")      # set() — no alphabetic chars
detect_scripts("")              # set()
```

---

## `is_mixed_script(text)`

Return `True` if the text contains characters from two or more scripts.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `text` | `str` | The string to check |

**Returns:** `bool` --- `True` when 2+ script buckets are detected.

Non-alphabetic characters (digits, punctuation, emoji) are not counted, so `"hello 123"` is not considered mixed.

**Examples:**

```python
from navi_sanitize import is_mixed_script

is_mixed_script("hello world")   # False — Latin only
is_mixed_script("pаypal.com")   # True — Latin + Cyrillic
is_mixed_script("Ꭺdmin")        # True — Cherokee + Latin
is_mixed_script("12345")         # False — no alphabetic chars
```
