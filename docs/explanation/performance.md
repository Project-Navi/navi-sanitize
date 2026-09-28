# Performance

## Measured Results

Measured with the suite in `tests/test_benchmark.py` on one workstation; each figure is the median across three runs. Treat these as a relative guide: absolute numbers depend on the machine and Python build.

**Conditions:** navi-sanitize 0.2.2 candidate runtime code, CPython 3.12.12, AMD Ryzen 9 9950X, Linux, pytest-benchmark 5.2.3, single thread, September 2026.

### `clean()` --- Per-String Cost

| Scenario | Median | Per second | Input |
|----------|--------|------------|-------|
| Short, clean text (no-op) | 1.2 µs | ~830K | ~38 chars, no stage changes anything |
| Short, hostile, with `jinja2_escaper` | 20.8 µs | ~48K | ~27 chars: homoglyphs, null byte, zero-width, template syntax |
| 13KB clean text | 310 µs | ~3.2K | Large no-op input |
| 10KB hostile, with `jinja2_escaper` | 296 µs | ~3.4K | Repeated hostile pattern |
| 100KB hostile, with `jinja2_escaper` | 3.4 ms | ~290 | Stress payload |

### `walk()` --- Nested Structure Cost

| Scenario | Median | Per second | Input |
|----------|--------|------------|-------|
| 100-item nested dict, clean | 345 µs | ~2.9K | Copy and traversal, no stage changes anything |
| 100-item nested dict, hostile | 2.4 ms | ~420 | Copy plus pipeline changes on every string |

### Opt-in Utilities and Escapers

| Scenario | Median | Per second | Input |
|----------|--------|------------|-------|
| `decode_evasion()`, double-encoded path | 10.1 µs | ~99K | `%252e%252e%252fetc%252fpasswd` |
| `decode_evasion()`, 12KB mixed encodings | 578 µs | ~1.7K | URL, HTML entity and `\xHH` escapes |
| `jinja2_escaper()`, 11KB overlapping delimiters | 806 µs | ~1.2K | Called directly |
| `path_escaper()`, 10KB of dot segments | 118 µs | ~8.5K | Called directly |

## Running Benchmarks

```bash
uv run pytest tests/test_benchmark.py -v             # everything
uv run pytest tests/test_benchmark.py -v -k clean    # clean() only
uv run pytest tests/test_benchmark.py -v -k walk     # walk() only
```

The 100KB payload uses `pedantic()` mode (50 rounds, 5 warmup) to avoid excessive iterations. Compare versions on the same machine and interpreter; CI runners are too noisy for small differences.

## When to Use `clean()` vs `walk()`

| Situation | Use |
|-----------|-----|
| Single user input field | `clean()` |
| JSON request body | `walk()` |
| Individual form fields already extracted | `clean()` on each |
| Nested config from untrusted source | `walk()` |

`walk()` builds new dicts and lists so the input is never modified. If you know which fields matter, calling `clean()` on those fields avoids copying the rest.

## Cost by Stage

| Stage | Cost | Notes |
|-------|------|-------|
| Null bytes | O(n) | `str.count` / `str.replace` |
| Invisible chars | O(n) | One compiled regex |
| NFKC normalization | O(n) | `unicodedata.normalize` (C implementation) |
| Homoglyphs | O(n) | NFD, per-character dict lookup, NFC |
| Escaper | Varies | Depends on the escaper |

Even for clean text every stage scans the whole string; the invisible-character regex and the normalization calls dominate.

## Hot Paths

**Sanitize once at the boundary** and store the result, rather than on every use.

**Printable ASCII is never changed** by the universal stages, so you can skip them for such input. Check `isprintable()` as well as `isascii()`: ASCII control characters such as ESC are stripped and must not take the shortcut. Apply your escaper either way:

```python
from navi_sanitize import clean

def clean_fast(text: str) -> str:
    if text.isascii() and text.isprintable():
        return text
    return clean(text)

safe = my_escaper(clean_fast(user_input))  # the escaper still runs
```

**Escaper cost:** the universal stages cost roughly the same for any input of a given size, so an expensive custom escaper is where optimization pays off.
