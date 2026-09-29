# tests/test_benchmark.py
"""Performance benchmarks for navi-sanitize.

Run: uv run pytest tests/test_benchmark.py --benchmark-only
"""

from __future__ import annotations

from pytest_benchmark.fixture import BenchmarkFixture

from navi_sanitize import clean, decode_evasion, jinja2_escaper, path_escaper, walk

# --- Test data ---

CLEAN_SHORT = "Hello, this is perfectly normal text."
CLEAN_LONG = "Hello world. " * 1000  # 13,000 chars

HOSTILE_SHORT = "n\u0430vi {{ c\u043enfig }}\x00\u200b"
HOSTILE_LONG = "n\u0430vi {{ c\u043enfig }}\x00\u200b " * 200  # 4,000 chars

HOSTILE_100K = HOSTILE_SHORT * 2500  # 47,500 chars (57,500 bytes UTF-8)

NESTED_CLEAN = {
    "users": [
        {"name": f"user_{i}", "email": f"user_{i}@example.com", "active": True} for i in range(100)
    ]
}

ENCODED_SHORT = "%252e%252e%252fetc%252fpasswd"
ENCODED_LONG = "%2e%2e%2f&lt;x&gt;\\x41 plain text " * 400  # 13,600 chars, mixed encodings
BRACES_LONG = "{{% x %}} {#}} {{{ " * 600  # 11,400 chars, overlapping delimiters
PATH_LONG = "a/.../b/../c/./d/" * 600  # 10,200 chars

NESTED_HOSTILE = {
    "users": [
        {"name": f"us\u0435r_{i}", "email": f"user\x00{i}@ex\u0430mple.com", "active": True}
        for i in range(100)
    ]
}


# --- clean() benchmarks ---


class TestCleanBenchmarks:
    def test_clean_short_noop(self, benchmark: BenchmarkFixture) -> None:
        """Baseline: clean text, no changes needed."""
        benchmark(clean, CLEAN_SHORT)

    def test_clean_short_hostile(self, benchmark: BenchmarkFixture) -> None:
        """Worst case short: all stages fire."""
        benchmark(clean, HOSTILE_SHORT, escaper=jinja2_escaper)

    def test_clean_long_noop(self, benchmark: BenchmarkFixture) -> None:
        """Large clean text throughput."""
        benchmark(clean, CLEAN_LONG)

    def test_clean_long_hostile(self, benchmark: BenchmarkFixture) -> None:
        """Large hostile text — all stages fire."""
        benchmark(clean, HOSTILE_LONG, escaper=jinja2_escaper)

    def test_clean_100k_hostile(self, benchmark: BenchmarkFixture) -> None:
        """47,500-char hostile payload throughput."""
        benchmark.pedantic(
            clean,
            args=(HOSTILE_100K,),
            kwargs={"escaper": jinja2_escaper},
            rounds=50,
            warmup_rounds=5,
        )


# --- walk() benchmarks ---


class TestWalkBenchmarks:
    def test_walk_nested_clean(self, benchmark: BenchmarkFixture) -> None:
        """100-item nested dict, clean values."""
        benchmark(walk, NESTED_CLEAN)

    def test_walk_nested_hostile(self, benchmark: BenchmarkFixture) -> None:
        """100-item nested dict, hostile values."""
        benchmark(walk, NESTED_HOSTILE)


# --- escaper and decoder benchmarks ---


class TestUtilityBenchmarks:
    def test_decode_short_nested(self, benchmark: BenchmarkFixture) -> None:
        """Double-encoded path: two decode layers."""
        benchmark(decode_evasion, ENCODED_SHORT)

    def test_decode_long_mixed(self, benchmark: BenchmarkFixture) -> None:
        """~12KB of mixed URL/HTML/hex encodings."""
        benchmark(decode_evasion, ENCODED_LONG)

    def test_jinja2_escaper_long(self, benchmark: BenchmarkFixture) -> None:
        """~11KB of overlapping delimiter runs."""
        benchmark(jinja2_escaper, BRACES_LONG)

    def test_path_escaper_long(self, benchmark: BenchmarkFixture) -> None:
        """~10KB path with dot segments."""
        benchmark(path_escaper, PATH_LONG)
