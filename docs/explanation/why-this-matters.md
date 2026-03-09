# Why This Matters

Untrusted text carries invisible attacks. Homoglyph substitution, zero-width characters, null bytes, fullwidth encoding, and template injection delimiters bypass validation, poison templates, fool humans, and evade detection. navi-sanitize removes these vectors before text reaches your application.

## Use Cases

### LLM Prompt Pipelines

User input flows into system prompts, RAG context, and tool calls. The attack surface is broad:

- **Tag block smuggling** --- Unicode Tag characters (U+E0001-U+E007F) encode invisible ASCII that tokenizers read but humans can't see. An attacker can embed `"ignore previous instructions"` in text that appears blank.
- **Homoglyph filter bypass** --- Keyword blocklists checking for `"system"` miss `"ѕуѕtеm"` (Cyrillic ѕ, у, е).
- **Zero-width injection** --- Invisible characters inserted between tokens alter how models parse input without visible change.

navi-sanitize strips all of these before text reaches the model. The pluggable escaper lets you add vendor-specific prompt escaping on top.

```python
from navi_sanitize import clean

# Strip invisible prompt injection before sending to LLM
sanitized_input = clean(user_message)

# With a custom prompt escaper
clean(user_message, escaper=my_prompt_escaper)
```

### Web Applications

Jinja2 SSTI, path traversal, and fullwidth encoding bypasses are well-known but tedious to cover manually:

- **Homoglyph-disguised SSTI** --- `{{ cоnfig }}` uses Cyrillic `о` (U+043E). A naive Jinja2 escaper sees ASCII `{` but the interior contains non-Latin characters, potentially confusing downstream processing. navi-sanitize normalizes *before* escaping.
- **Fullwidth bypass** --- `\uff7b\uff6f\uff73\uff72\uff9e` renders as fullwidth katakana but NFKC normalizes to ASCII that may match dangerous patterns.
- **Path traversal + null byte** --- `"../\x00../../etc/passwd"` combines null byte truncation with directory traversal. The pipeline removes null bytes first, then the path escaper strips traversal sequences.

```python
from navi_sanitize import clean, jinja2_escaper, path_escaper

# Single call handles homoglyphs + template escaping
clean("{{ cоnfig }}", escaper=jinja2_escaper)

# Path sanitization after null byte removal
clean("../\x00../../etc/passwd", escaper=path_escaper)
```

### Config and Data Ingestion

YAML, TOML, and JSON parsed from untrusted sources can carry:

- **Null bytes** that truncate C-extension string processing, causing key mismatches
- **Zero-width characters** that break key matching (`"api\u200b_key"` looks like `"api_key"` but doesn't match)
- **Homoglyphs** that create near-duplicate keys (`"аpi_key"` with Cyrillic `а` coexists with `"api_key"`)

`walk()` sanitizes every string in a nested structure in one call:

```python
from navi_sanitize import walk

# Sanitize entire parsed config
config = walk(yaml.safe_load(untrusted_yaml))

# With escaper for template configs
config = walk(parsed_json, escaper=jinja2_escaper)
```

### Log Analysis and SIEM

Attackers embed invisible characters in log entries to evade detection:

- **Bidi overrides** reorder displayed text, hiding malicious content from analysts reviewing logs visually
- **Zero-width characters** break grep patterns (`"admin"` won't match `"adm\u200bin"`)
- **Tag block characters** encode invisible metadata that log aggregation tools may index but analysts can't see

Sanitizing log data on ingest ensures what you search is what's actually there:

```python
from navi_sanitize import clean

def sanitize_log_entry(entry: str) -> str:
    return clean(entry)
```

### Identity and Anti-Phishing

`pаypal.com` (Cyrillic `а`) renders identically to `paypal.com` in most fonts. This applies to:

- **Display names** in messaging and email
- **URLs** in link previews and bookmarks
- **Email addresses** in sender fields
- **Usernames** in registration systems

Homoglyph replacement normalizes these to catch spoofing that visual inspection misses:

```python
from navi_sanitize import clean

# Normalize display name before showing to user
display_name = clean(untrusted_name)

# Normalize URL for comparison
if clean(submitted_url) != submitted_url:
    flag_as_suspicious(submitted_url)
```

### Database and Search

When users can create content that others search:

- Homoglyphs create duplicate entries that appear identical but don't match queries
- Invisible characters cause full-text search misses
- NFKC normalization ensures that `"cafe"` and `"café"` (with combining acute accent) are consistently stored

Sanitize at the write boundary:

```python
from navi_sanitize import clean

# Normalize before storing
record["title"] = clean(user_input)
```

## Integration Points

navi-sanitize is designed to compose with existing tools:

| Layer | Tool | How They Compose |
|-------|------|-----------------|
| Validation | pydantic, cerberus | Call `clean()` in an `AfterValidator` or coercion chain |
| HTML escaping | MarkupSafe, nh3 | navi-sanitize normalizes characters; MarkupSafe escapes HTML entities |
| Encoding repair | ftfy | Run ftfy first to fix mojibake, then navi-sanitize to strip evasion vectors |
| Template engines | Jinja2 | Use `jinja2_escaper` *and* Jinja2's `autoescape=True` for defense in depth |
| Web frameworks | Django, Flask, FastAPI | Sanitize at the request boundary in middleware or dependency injection |
| LLM frameworks | LangChain, LlamaIndex | Sanitize user input before it enters the prompt pipeline |
