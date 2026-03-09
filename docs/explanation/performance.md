# Performance

Benchmarks measured on Python 3.12, single thread. Run via `uv run pytest tests/test_benchmark.py -v`.

## Benchmark Results

### `clean()` --- Per-String Cost

| Scenario | Mean | Ops/sec | Description |
|----------|------|---------|-------------|
| Short, clean text (no-op) | 2.8 us | 358K | ~38 chars, no stages fire |
| Short, hostile (all stages) | 67 us | 15K | ~27 chars with homoglyphs, null bytes, zero-width, template syntax |
| 13KB clean text | 810 us | 1.2K | Large clean input throughput |
| 10KB hostile text | 449 us | 2.2K | Large hostile input with repeated attack patterns |
| 100KB hostile payload | 5.7 ms | 176 | Stress test payload |

### `walk()` --- Recursive Structure Cost

| Scenario | Mean | Ops/sec | Description |
|----------|------|---------|-------------|
| 100-item nested dict, clean | 537 us | 1.9K | `deepcopy` + traversal overhead, no stages fire |
| 100-item nested dict, hostile | 6.9 ms | 144 | `deepcopy` + full pipeline on every string |

## When to Use `clean()` vs `walk()`

| Situation | Use |
|-----------|-----|
| Single user input field | `clean()` |
| JSON request body | `walk()` |
| Individual form fields already extracted | `clean()` on each |
| Nested config from untrusted source | `walk()` |
| Hot path, single known string | `clean()` |

`walk()` adds `deepcopy` overhead to ensure the original data is never modified. If you're already working with a copy or don't need immutability, you can call `clean()` on individual strings for better performance.

## Performance Characteristics by Stage

| Stage | Cost Profile | Notes |
|-------|-------------|-------|
| Null bytes | O(n) | `str.replace` --- very fast |
| Invisible chars | O(n) | Single compiled regex --- fast |
| NFKC normalization | O(n) | `unicodedata.normalize` --- C implementation |
| Homoglyphs | O(n) | Character-by-character dict lookup --- fast for short strings, linear for long |
| Escaper | Varies | Depends on escaper implementation |

All stages are O(n) in string length. The pipeline makes a single pass per stage (5 passes total). The dominant cost for clean text is the invisible character regex and NFKC normalization (the regex `findall` check and `unicodedata.normalize` still scan the full string).

## Tips for Hot Paths

**Batch at the boundary:** Sanitize input once when it enters your system, not on every use. Store the sanitized version.

**Skip `walk()` when possible:** If you know the structure of your data, calling `clean()` on specific fields avoids `deepcopy` overhead.

**Pre-check with `is_ascii()`:** If you know your input is pure ASCII, you can skip sanitization entirely --- none of the universal stages modify ASCII text (except null bytes, which are rare in text input).

```python
def sanitize_if_needed(text: str, **kwargs) -> str:
    if text.isascii() and "\x00" not in text:
        return text
    return clean(text, **kwargs)
```

**Escaper cost:** The universal stages are fixed-cost. If your custom escaper is expensive, that's where optimization efforts should focus.

## Running Benchmarks

```bash
# Run all benchmarks
uv run pytest tests/test_benchmark.py -v

# Run only clean() benchmarks
uv run pytest tests/test_benchmark.py -v -k "clean"

# Run only walk() benchmarks
uv run pytest tests/test_benchmark.py -v -k "walk"
```

Benchmarks use `pytest-benchmark`. The 100KB payload test uses `pedantic()` mode (50 rounds, 5 warmup) to avoid excessive iterations.
