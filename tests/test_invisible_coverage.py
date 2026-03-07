# SPDX-License-Identifier: MIT
"""Regression test: verify INVISIBLE_RE matches all 492 intended codepoints.

Guards against silent regex regressions from merge conflicts, set ordering
changes, or range edits. See issue #8 for the planned refactor.
"""

from __future__ import annotations

import unicodedata

from navi_sanitize._invisible import (
    BIDI_CONTROL_CHARS,
    C0_CONTROL_RANGES,
    C1_CONTROL_RANGE,
    FORMAT_CHARS,
    INVISIBLE_RE,
    MONGOLIAN_FVS_CHARS,
    TAG_BLOCK_RANGE,
    VARIATION_SELECTOR_RANGE,
    VARIATION_SELECTOR_SUPPLEMENT_RANGE,
    ZERO_WIDTH_CHARS,
)

EXPECTED_COUNT = 492


def _build_expected_codepoints() -> set[int]:
    """Build the complete set of codepoints from data structures."""
    cps: set[int] = set()

    # Individual char sets
    for char_set in (ZERO_WIDTH_CHARS, FORMAT_CHARS, MONGOLIAN_FVS_CHARS, BIDI_CONTROL_CHARS):
        cps |= {ord(ch) for ch in char_set}

    # Contiguous ranges
    for start, end in [
        VARIATION_SELECTOR_RANGE,
        TAG_BLOCK_RANGE,
        VARIATION_SELECTOR_SUPPLEMENT_RANGE,
        C1_CONTROL_RANGE,
    ]:
        cps |= set(range(start, end + 1))

    # C0 sub-ranges
    for start, end in C0_CONTROL_RANGES:
        cps |= set(range(start, end + 1))

    return cps


class TestInvisibleRegexCoverage:
    """Verify the compiled regex matches every intended codepoint."""

    def test_expected_count(self) -> None:
        """Data structures define exactly 492 unique codepoints."""
        cps = _build_expected_codepoints()
        assert len(cps) == EXPECTED_COUNT, f"Expected {EXPECTED_COUNT}, got {len(cps)}"

    def test_regex_matches_all_codepoints(self) -> None:
        """INVISIBLE_RE matches every codepoint in the data structures."""
        cps = _build_expected_codepoints()
        missed: list[str] = []
        for cp in sorted(cps):
            ch = chr(cp)
            if not INVISIBLE_RE.search(ch):
                name = unicodedata.name(ch, f"U+{cp:04X}")
                missed.append(f"U+{cp:04X} ({name})")
        assert not missed, f"Regex missed {len(missed)} codepoints: {missed[:10]}"

    def test_regex_does_not_match_safe_chars(self) -> None:
        """INVISIBLE_RE does not match printable ASCII, TAB, LF, CR, or NUL."""
        safe = [*list(range(0x20, 0x7F)), 0x09, 0x0A, 0x0D, 0x00]
        false_positives: list[str] = []
        for cp in safe:
            ch = chr(cp)
            if INVISIBLE_RE.search(ch):
                false_positives.append(f"U+{cp:04X} ({ch!r})")
        assert not false_positives, f"Regex falsely matched: {false_positives}"


class TestUnicodeVersionAssumption:
    """Document the Unicode version assumption for normalization behavior."""

    def test_unicode_version_documented(self) -> None:
        """Assert the Unicode version so normalization changes are caught."""
        version = unicodedata.unidata_version
        major = int(version.split(".")[0])
        assert major >= 15, (
            f"Tests developed against Unicode 15.x+, got {version}. "
            "NFD/NFC/NFKC behavior may differ — review homoglyph bypass tests."
        )
