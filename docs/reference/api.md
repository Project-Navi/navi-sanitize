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
5. Re-NFKC (if homoglyphs were replaced, so the output stays NFKC-normalized)
6. Escaper (if provided)

Returns output for any `str`, including lone surrogates. Logs a warning with a count (never content) when a stage changes the input. Escaper output is not re-sanitized, and exceptions raised by the escaper propagate.

Without an escaper, `clean(clean(x)) == clean(x)`. With an escaper this is not promised, because escaper output is not re-normalized; see `path_escaper` below for a concrete case.

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

## `walk(data, *, escaper=None, max_depth=128)`

Sanitize every string in a nested dict/list structure, dict keys included.

Uses PEP 695 generic syntax: `def walk[T](data: T, *, escaper=None, max_depth=128) -> T`

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | `T` | *(required)* | Any Python object; strings within dicts/lists are sanitized |
| `escaper` | `Escaper \| None` | `None` | Optional escaper applied to each string, keys included |
| `max_depth` | `int` | `128` | Advisory warning threshold, not a limit (see below). `ValueError` if negative |

**Returns:** `T` --- new dicts and lists with every string sanitized; other objects are the originals.

**Raises:** `ValueError` --- if `max_depth` is negative. `TypeError` from `clean()` (for example, an escaper returning a non-`str`) and escaper exceptions propagate.

**Behavior by type:**

| Type | Behavior |
|------|----------|
| `str` | Passed through `clean()` |
| `dict` (and subclasses) | Rebuilt as a plain `dict`; keys and values sanitized |
| `list` (and subclasses) | Rebuilt as a plain `list`; elements sanitized |
| `tuple`, `set`, `frozenset`, `bytes`, other objects | Returned as the same object, not traversed |
| `int`, `float`, `bool`, `None` | Returned unchanged |

The input is **never modified**. `walk()` makes one iterative pass (no recursion, no `deepcopy`): each dict and list is copied once, and cycles and shared containers keep their shape in the copy.

**Key collisions:** if distinct keys sanitize (or escape) to the same key, the last value is kept at the first key's position and one warning per affected dict reports the count: `walk() dict key collision: 1 key(s) sanitized to an existing key; last value kept`. `walk()` is lossy in that case; validate keys yourself where distinct keys matter.

**Depth threshold:** the top-level container is depth 0. The first time a container is reached at depth `>= max_depth`, one warning is logged and sanitizing continues. A container shared by several paths (or part of a cycle) is visited once, at the depth where it is first reached, so the threshold does not measure the longest path.

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

# Custom depth limit
walk(deep_structure, max_depth=256)

# Warning on excessive nesting (continues sanitizing)
walk(hostile_json)  # logs: "walk() input exceeds max_depth=128; continuing to sanitize"
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

**Returns:** `str` --- the string with Jinja2's default delimiters backslash-escaped.

**What it escapes:**
- `{{` and `}}` --- expression delimiters
- `{%` and `%}` --- statement delimiters
- `{#` and `#}` --- comment delimiters
- Brace runs (`{{{`, `}}}`) and overlapping sequences (`{{%`, `{%}`, `%}}`)

Each match is a maximal chain of overlapping delimiters, and every character in it is backslash-escaped, so the result contains no adjacent delimiter pair and escaping twice changes nothing.

**Limits:** it only breaks up the default delimiters. It does not handle custom `Environment` delimiter settings, escape HTML, validate or sandbox templates, and the backslashes appear literally if the text is rendered. Prefer passing untrusted text to templates as context data.

**Examples:**

```python
from navi_sanitize import jinja2_escaper

jinja2_escaper("{{ config }}")     # "\\{\\{ config \\}\\}"
jinja2_escaper("{% import os %}")  # "\\{\\% import os \\%\\}"
jinja2_escaper("{# comment #}")    # "\\{\\# comment \\#\\}"
jinja2_escaper("{{{ triple }}}")   # "\\{\\{\\{ triple \\}\\}\\}"
jinja2_escaper("{{%")              # "\\{\\{\\%"
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
4. Delete every `..` inside each segment (handles null-byte concatenation artifacts, e.g. `file..txt` becomes `filetxt`)
5. Drop segments that are then empty or `.`
6. Rejoin the remaining segments

The result never contains an empty, `.` or `..` segment, and applying the escaper again changes nothing.

**Composition:** Because escaper output is not re-normalized, the idempotence of `clean()` does not extend to every final-escaper composition: `clean('e..\u0301', escaper=path_escaper)` returns `'e\u0301'` (deleting `..` leaves a base letter next to a combining accent), and a second identical call returns `'\u00e9'`. The escaper itself is idempotent; re-running the whole pipeline over its output can still change it. For the same reason, a second `walk(..., escaper=path_escaper)` pass can merge keys such as `'e..\u0301'` and `'\u00e9'` that stayed distinct on the first pass.

**Limits:** lexical string cleanup only. It does not confine the path to a base directory, resolve symlinks, touch the filesystem, or handle drive-qualified paths (`C:/temp` passes through), and it can return an empty string. Join the result to your base directory and check containment before use.

**Examples:**

```python
from navi_sanitize import path_escaper

path_escaper("../../../etc/passwd")    # "etc/passwd"
path_escaper("/etc/passwd")            # "etc/passwd"
path_escaper("foo/../../../bar")       # "foo/bar"
path_escaper("..\\..\\windows\\cmd")   # "windows/cmd"
path_escaper("safe/path/file.txt")     # "safe/path/file.txt"
path_escaper(".../file")               # "file"
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

**Raises:** `TypeError` --- if `text` is not a `str`.

**Behavior:**
- Runs URL decoding → HTML entity unescaping → hex escape decoding (`\xHH`) per pass
- A pass counts as one layer if the output differs from the input
- Stops when a pass produces no change or `max_layers` is reached
- `max_layers <= 0` is a no-op (returns `text` unchanged)
- Does not raise on string content of any length. Undecodable percent bytes stay as `%XX` text and malformed `\xHH` escapes are left alone
- HTML references follow Python's HTML5 rules (`html.unescape`), so some invalid references are replaced or dropped rather than kept: `&#0;` and out-of-range values such as `&#1114112;` become U+FFFD, `&#128;` becomes `€`, and some control-character references are removed. Decimal references of any length are handled (leading zeros are ignored)
- Literal characters, including lone surrogates, are never re-encoded; only `%XX` runs are percent-decoded
- Decodes only these three formats; base64 and other encodings are left alone
- Logs a warning with the layer count when decoding occurs; never includes decoded content in log messages

**Examples:**

```python
from navi_sanitize import decode_evasion, clean, path_escaper

# Single layer of URL encoding
decode_evasion("%2e%2e%2fetc%2fpasswd")       # "../etc/passwd"

# Double-encoded (two layers)
decode_evasion("%252e%252e%252fetc%252fpasswd")  # "../etc/passwd"

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

Only the listed buckets are returned; this is a heuristic based on the first word of each character's Unicode name, not a full Unicode Script property lookup. Characters from other scripts are ignored, and non-alphabetic characters (digits, punctuation, emoji) are skipped.

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
