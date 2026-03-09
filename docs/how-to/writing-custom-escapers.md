# Writing Custom Escapers

navi-sanitize's pipeline has five universal stages followed by a pluggable escaper. This page explains how to write your own escapers for contexts not covered by the built-in `jinja2_escaper` and `path_escaper`.

## The Escaper Contract

An escaper is any function with the signature:

```python
def my_escaper(text: str) -> str:
    ...
```

**Rules:**
1. Accept a `str`, return a `str` (raises `TypeError` otherwise)
2. Runs **after** all universal stages (null bytes, invisibles, NFKC, homoglyphs are already handled)
3. Output is **not** re-sanitized --- what you return is the final result
4. Should be **idempotent** --- applying it twice should produce the same result as once
5. Should be **pure** --- no side effects, no state

## Example: HTML Escaper

For cases where you're building HTML strings manually (not using a template engine):

```python
import html

def html_escaper(text: str) -> str:
    """Escape HTML special characters."""
    return html.escape(text, quote=True)
```

Usage:

```python
from navi_sanitize import clean

clean('<script>alert("xss")</script>', escaper=html_escaper)
# '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
```

## Example: SQL Identifier Escaper

For sanitizing values used as SQL identifiers (table names, column names) --- **not a substitute for parameterized queries:**

```python
def sql_identifier_escaper(text: str) -> str:
    """Escape a SQL identifier by doubling quotes and wrapping."""
    # Remove characters not valid in identifiers
    cleaned = "".join(c for c in text if c.isalnum() or c == "_")
    return cleaned
```

Usage:

```python
from navi_sanitize import clean

column = clean(user_input, escaper=sql_identifier_escaper)
# Use in a query where parameterization isn't possible (e.g., ORDER BY)
```

## Example: Composing Multiple Escapers

You can compose escapers to apply multiple context-specific transformations:

```python
from navi_sanitize import clean, jinja2_escaper, path_escaper, Escaper

def compose(*escapers: Escaper) -> Escaper:
    """Chain multiple escapers into one."""
    def composed(text: str) -> str:
        for escaper in escapers:
            text = escaper(text)
        return text
    return composed

# Escaper that handles both Jinja2 and path traversal
combined = compose(jinja2_escaper, path_escaper)
clean(user_input, escaper=combined)
```

**Order matters** in composition --- the first escaper's output becomes the second's input. Consider whether one escaper's transformations could interfere with another's.

## Example: LLM Prompt Escaper Skeleton

LLM prompt injection prevention is vendor-specific and evolving. Here's a skeleton you can adapt:

```python
import re

def prompt_escaper(text: str) -> str:
    """Escape common LLM prompt injection patterns.

    Adapt this to your specific LLM vendor's syntax.
    """
    # Example: fence user content in XML-style tags
    text = text.replace("<", "&lt;").replace(">", "&gt;")

    # Example: escape common injection prefixes
    patterns = [
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        r"(?i)system\s*:",
        r"(?i)<\|?(system|user|assistant)\|?>",
    ]
    for pattern in patterns:
        text = re.sub(pattern, "[FILTERED]", text)

    return text
```

> **Note:** navi-sanitize intentionally does not ship an LLM prompt escaper because vendor syntax evolves rapidly. The pluggable design lets you maintain your own.

## Testing Escapers

Test that your escaper handles edge cases:

```python
import pytest
from navi_sanitize import clean

def test_my_escaper_basic():
    assert clean("normal text", escaper=my_escaper) == "normal text"

def test_my_escaper_handles_target():
    """Test the specific threat your escaper addresses."""
    result = clean(malicious_input, escaper=my_escaper)
    assert dangerous_pattern not in result

def test_my_escaper_with_universal_stages():
    """Ensure your escaper works after homoglyph/invisible removal."""
    # Cyrillic + your target pattern
    result = clean(combined_attack, escaper=my_escaper)
    assert result == expected_safe_output

def test_my_escaper_idempotent():
    """Applying the escaper twice should be safe."""
    once = my_escaper("dangerous input")
    twice = my_escaper(once)
    assert once == twice

def test_my_escaper_returns_str():
    """Escaper must return str."""
    result = my_escaper("test")
    assert isinstance(result, str)
```

Run tests:

```bash
uv run pytest tests/ -v --benchmark-disable
```

## Integration with `walk()`

Escapers work identically with `walk()`:

```python
from navi_sanitize import walk

clean_data = walk(untrusted_json, escaper=my_escaper)
```

Every string in the structure (including dict keys) passes through all universal stages and then your escaper.
