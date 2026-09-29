# Writing Custom Escapers

The pipeline runs its universal stages, then an optional escaper that prepares the text for one destination. This page covers writing your own for destinations the built-in `jinja2_escaper` and `path_escaper` do not cover.

## The Escaper Contract

An escaper is any function with the signature:

```python
def my_escaper(text: str) -> str:
    ...
```

**Rules:**

1. Accept a `str` and return a `str`; `clean()` raises `TypeError` for any other return type
2. It runs **after** the universal stages, so null bytes, invisibles, NFKC and mapped homoglyphs are already handled
3. Its output is **not** re-sanitized --- what you return is the final result, including any characters you add
4. Exceptions it raises propagate to the caller of `clean()` / `walk()`
5. Prefer pure functions; make them idempotent where the format allows, and otherwise make sure each value is escaped exactly once

## Example: HTML Text Escaper

For text you insert into HTML yourself. A template engine with autoescaping is the better choice when you have one.

```python
import html

def html_escaper(text: str) -> str:
    return html.escape(text, quote=True)
```

```python
from navi_sanitize import clean

clean('<script>alert("xss")</script>', escaper=html_escaper)
# '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
```

`html.escape` is not idempotent (`&` becomes `&amp;` again on a second pass), so escape each value once, at output time.

## Example: SQL Identifier Allowlist

For identifiers (such as a sort column) that cannot be parameterized. This is not a substitute for parameterized queries, and you should still check the result against the identifiers you actually allow:

```python
def sql_identifier_escaper(text: str) -> str:
    """Keep only letters, digits and underscores."""
    return "".join(c for c in text if c.isalnum() or c == "_")
```

```python
from navi_sanitize import clean

column = clean(user_input, escaper=sql_identifier_escaper)
if column not in {"name", "created_at"}:
    raise ValueError("unsupported sort column")
```

## Example: Composing Escapers

```python
from navi_sanitize import Escaper, clean, jinja2_escaper, path_escaper

def compose(*escapers: Escaper) -> Escaper:
    """Apply escapers left to right."""
    def composed(text: str) -> str:
        for escaper in escapers:
            text = escaper(text)
        return text
    return composed

path_then_jinja = compose(path_escaper, jinja2_escaper)
clean("../{{ x }}", escaper=path_then_jinja)  # '\\{\\{ x \\}\\}'
```

**Order matters.** `path_escaper` turns backslashes into `/`, so running it *after* `jinja2_escaper` would rewrite the backslashes that escaper just added. Put the escaper whose output must survive last.

## LLM Prompts

navi-sanitize does not ship a prompt escaper: vendor syntax changes quickly, and no character-level escaper stops instructions written in plain text. If your prompt format reserves delimiters, an escaper can keep untrusted text from forging them:

```python
def fence_escaper(text: str) -> str:
    """Stop user text from closing a <user_input> ... </user_input> fence."""
    return text.replace("<", "&lt;").replace(">", "&gt;")
```

Treat this as one layer. Model-side defenses, least-privilege tools and human review still apply.

## Testing Escapers

```python
from navi_sanitize import clean

def test_escaper_leaves_normal_text_alone():
    assert clean("normal text", escaper=my_escaper) == "normal text"

def test_escaper_neutralizes_its_target():
    assert dangerous_pattern not in clean(malicious_input, escaper=my_escaper)

def test_escaper_runs_after_universal_stages():
    # e.g. a fullwidth or homoglyph variant of your target
    assert dangerous_pattern not in clean(disguised_input, escaper=my_escaper)

def test_escaper_is_idempotent_where_expected():
    once = my_escaper("dangerous input")
    assert my_escaper(once) == once
```

## Integration with `walk()`

Escapers work the same way with `walk()`, and apply to dict keys as well as values:

```python
from navi_sanitize import walk

clean_data = walk(untrusted_json, escaper=my_escaper)
```

If your escaper maps different keys to the same string, `walk()` keeps the last value and logs a collision warning.
