# Why This Matters

Text that looks the same can differ underneath. Zero-width and control characters hide inside strings, fullwidth and other compatibility forms spell ASCII words with different code points, and lookalike letters from other scripts pass for Latin. Filters, comparisons, search and human reviewers can all be fooled. navi-sanitize normalizes those character-level differences before the text reaches your application. It does not judge intent or block anything.

## Use Cases

### LLM Prompt Pipelines

- **Tag-block smuggling** --- Unicode Tag characters (U+E0000--U+E007F) mirror ASCII but render as nothing, so text can carry instructions a reviewer cannot see.
- **Keyword filter evasion** --- a blocklist entry `"system"` misses `"ѕуѕtеm"` spelled with Cyrillic ѕ, у and е.
- **Zero-width padding** --- invisible characters split tokens without any visible change.

`clean()` removes tag and zero-width characters and replaces the mapped lookalikes. It cannot tell an instruction from ordinary text: prompt injection written in plain language passes through unchanged.

```python
from navi_sanitize import clean

sanitized = clean(user_message)
```

### Web Applications

- **Fullwidth delimiters** --- `｛｛ config ｝｝` uses fullwidth braces that NFKC turns into `{{ config }}`. An escaper that runs before normalization never sees the braces; with navi-sanitize the escaper runs after NFKC:

    ```python
    from navi_sanitize import clean, jinja2_escaper

    clean("｛｛ config ｝｝", escaper=jinja2_escaper)  # '\\{\\{ config \\}\\}'
    ```

- **Traversal split by null bytes** --- `"../\x00../../etc/passwd"` becomes `"../../../etc/passwd"` once the null byte is removed; `path_escaper` then strips the traversal segments.

Keep templates trusted and pass untrusted values as data; see the [threat model](threat-model.md#jinja2-template-injection-ssti).

### Config and Data Ingestion

Parsed YAML, TOML or JSON from untrusted sources can carry null bytes, zero-width characters that make `"api\u200b_key"` differ from `"api_key"`, and lookalike keys such as `"аpi_key"` with a Cyrillic `а`. `walk()` sanitizes every string, keys included:

```python
from navi_sanitize import walk

config = walk(json.loads(untrusted_json))
```

Sanitizing keys can make two keys identical; `walk()` then keeps the last value and logs a collision warning. Validate the result if key identity matters.

### Log Analysis

Bidi overrides reorder what an analyst sees, and zero-width characters break searches (`"admin"` does not match `"adm\u200bin"`). Sanitizing on ingest makes searches match the stored text:

```python
from navi_sanitize import clean

def sanitize_log_entry(entry: str) -> str:
    return clean(entry)
```

### Identity and Anti-Phishing

`pаypal.com` with a Cyrillic `а` renders like `paypal.com`. Normalizing display names, usernames and URLs before comparison catches the mapped lookalikes; comparing the raw and cleaned forms, or calling `is_mixed_script()` on the raw input, gives a spoofing signal:

```python
from navi_sanitize import clean, is_mixed_script

if clean(submitted_url) != submitted_url or is_mixed_script(submitted_url):
    flag_as_suspicious(submitted_url)
```

Mapped letters are replaced even in legitimate Cyrillic or Greek text, so decide per field whether that is acceptable.

### Database and Search

Invisible characters and compatibility forms make equal-looking strings compare unequal. NFKC also makes a precomposed `é` and `e` + combining acute accent identical, so either spelling stores and matches the same way:

```python
from navi_sanitize import clean

record["title"] = clean(user_input)
```

## Integration Points

| Layer | Tool | How they compose |
|-------|------|------------------|
| Validation | pydantic, cerberus | Call `clean()` in an `AfterValidator` or coercion chain |
| HTML escaping | MarkupSafe, nh3 | navi-sanitize normalizes characters; the HTML tool escapes or sanitizes markup |
| Encoding repair | ftfy | Repair mojibake first, then sanitize |
| Templates | Jinja2 | Trusted templates, untrusted values as data, `autoescape=True` for HTML |
| Web frameworks | Django, Flask, FastAPI | Sanitize at the request boundary |
| LLM frameworks | LangChain, LlamaIndex | Sanitize user input before it enters the prompt |
