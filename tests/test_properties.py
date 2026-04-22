# SPDX-License-Identifier: MIT
"""Property-based tests for navi-sanitize invariants.

Uses hypothesis to generate adversarial inputs and verify that every
public API function upholds its documented contracts.

Run: uv run pytest tests/test_properties.py -v --benchmark-disable
Profiles: --hypothesis-profile=ci (500 examples) or security (10000)
"""

from __future__ import annotations

import re
import unicodedata

import hypothesis.strategies as st
from hypothesis import given, settings

from navi_sanitize import (
    clean,
    decode_evasion,
    detect_scripts,
    is_mixed_script,
    jinja2_escaper,
    path_escaper,
    walk,
)
from navi_sanitize._homoglyphs import HOMOGLYPH_MAP
from navi_sanitize._invisible import INVISIBLE_RE

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

KNOWN_SCRIPTS = frozenset(
    {"latin", "cyrillic", "greek", "arabic", "hebrew", "armenian", "cherokee", "cjk"}
)

# Characters that exercise the pipeline stages
_HOSTILE_ALPHABET = (
    "\x00"  # null byte
    "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff"  # zero-width
    "\u202a\u202b\u202e\u2066\u2069"  # bidi
    "\u00ad\u034f\u2009\u200a"  # format chars
    "\u0430\u0435\u043e\u0440\u0441"  # Cyrillic homoglyphs
    "\u0391\u0392\u0395\u039f\u03a1"  # Greek homoglyphs
    "\u2212\u2013\u2014\u2018\u2019\u201c\u201d"  # typographic
    "\uff41\uff42\uff43"  # fullwidth Latin
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " \t\n"
    "!@#$%^&*(){}[]<>/\\|"
    "{{ }} {% %} {# #}"
    "../../"
)

HOSTILE_TEXT = st.text(alphabet=_HOSTILE_ALPHABET, min_size=0, max_size=200)
UNICODE_TEXT = st.text(min_size=0, max_size=200)
SAFE_TEXT = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789 .-_",
    min_size=0,
    max_size=100,
)

# Jinja2 delimiter regex (matches raw, unescaped delimiters)
_JINJA2_DELIMITERS_RE = re.compile(r"\{{2,}|\}{2,}|\{%|%\}|\{#|#\}")


def _nested_structure(leaf: st.SearchStrategy[object]) -> st.SearchStrategy[object]:
    """Build nested dict/list structures with st.recursive()."""
    return st.recursive(
        leaf,
        lambda children: st.one_of(
            st.dictionaries(
                keys=st.text(min_size=0, max_size=20),
                values=children,
                min_size=0,
                max_size=5,
            ),
            st.lists(children, min_size=0, max_size=5),
        ),
        max_leaves=20,
    )


walk_structure = _nested_structure(
    st.one_of(
        HOSTILE_TEXT,
        st.integers(min_value=-1000, max_value=1000),
        st.none(),
        st.booleans(),
        st.floats(allow_nan=False, allow_infinity=False),
    ),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_leaf_strings(data: object) -> list[str]:
    """Extract all leaf strings from a dict/list structure."""
    result: list[str] = []
    stack: list[object] = [data]
    seen: set[int] = set()
    while stack:
        item = stack.pop()
        obj_id = id(item)
        if obj_id in seen:
            continue
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            seen.add(obj_id)
            stack.extend(item.values())
        elif isinstance(item, list):
            seen.add(obj_id)
            stack.extend(item)
    return result


# ---------------------------------------------------------------------------
# clean() invariants
# ---------------------------------------------------------------------------


class TestCleanProperties:
    """Property-based tests for clean() invariants."""

    @given(text=UNICODE_TEXT)
    @settings(max_examples=50)
    def test_always_returns_str(self, text: str) -> None:
        assert isinstance(clean(text), str)

    @given(text=HOSTILE_TEXT)
    @settings(max_examples=50)
    def test_no_null_bytes(self, text: str) -> None:
        assert "\x00" not in clean(text)

    @given(text=HOSTILE_TEXT)
    @settings(max_examples=50)
    def test_no_invisible_characters(self, text: str) -> None:
        assert not INVISIBLE_RE.search(clean(text))

    @given(text=HOSTILE_TEXT)
    @settings(max_examples=50)
    def test_no_homoglyphs(self, text: str) -> None:
        result = clean(text)
        remaining = set(result) & set(HOMOGLYPH_MAP)
        assert not remaining, f"Homoglyphs remain: {remaining!r}"

    @given(text=UNICODE_TEXT)
    @settings(max_examples=50)
    def test_nfkc_stable(self, text: str) -> None:
        result = clean(text)
        assert unicodedata.normalize("NFKC", result) == result

    @given(text=UNICODE_TEXT)
    @settings(max_examples=50)
    def test_idempotent(self, text: str) -> None:
        first = clean(text)
        assert clean(first) == first

    @given(text=HOSTILE_TEXT)
    @settings(max_examples=50)
    def test_idempotent_hostile(self, text: str) -> None:
        first = clean(text)
        assert clean(first) == first


# ---------------------------------------------------------------------------
# walk() invariants
# ---------------------------------------------------------------------------


class TestWalkProperties:
    """Property-based tests for walk() invariants."""

    @given(data=walk_structure)
    @settings(max_examples=50)
    def test_never_mutates_original(self, data: object) -> None:
        import copy

        original = copy.deepcopy(data)
        walk(data)
        assert data == original

    @given(data=walk_structure)
    @settings(max_examples=50)
    def test_leaf_strings_are_clean(self, data: object) -> None:
        result = walk(data)
        for s in _collect_leaf_strings(result):
            assert "\x00" not in s
            assert not INVISIBLE_RE.search(s)
            remaining = set(s) & set(HOMOGLYPH_MAP)
            assert not remaining, f"Homoglyph in walk output: {remaining!r}"
            assert unicodedata.normalize("NFKC", s) == s

    @given(data=walk_structure)
    @settings(max_examples=50)
    def test_preserves_structure_type(self, data: object) -> None:
        result = walk(data)
        if isinstance(data, (dict, list, str)):
            assert type(result) is type(data)
        else:
            assert result == data

    @given(depth=st.integers(min_value=1, max_value=200))
    @settings(max_examples=20)
    def test_handles_any_depth(self, depth: int) -> None:
        data: object = "test"
        for _ in range(depth):
            data = {"k": data}
        result = walk(data)
        assert isinstance(result, dict)

    def test_handles_cycle(self) -> None:
        a: dict[str, object] = {"val": "hello"}
        a["self"] = a
        result = walk(a)
        leaf = result["val"]
        assert leaf == "hello"
        # Leaf strings in cyclic structures should still satisfy clean() invariants.
        assert "\x00" not in leaf
        assert not INVISIBLE_RE.search(leaf)
        remaining = set(leaf) & set(HOMOGLYPH_MAP)
        assert not remaining, f"Homoglyph in walk output: {remaining!r}"
        assert unicodedata.normalize("NFKC", leaf) == leaf
        assert result["self"] is result


# ---------------------------------------------------------------------------
# detect_scripts() / is_mixed_script() invariants
# ---------------------------------------------------------------------------


class TestScriptDetectionProperties:
    """Property-based tests for script detection."""

    @given(text=UNICODE_TEXT)
    @settings(max_examples=50)
    def test_returns_subset_of_known_scripts(self, text: str) -> None:
        assert detect_scripts(text) <= KNOWN_SCRIPTS

    @given(text=UNICODE_TEXT)
    @settings(max_examples=50)
    def test_is_mixed_consistent(self, text: str) -> None:
        assert is_mixed_script(text) == (len(detect_scripts(text)) >= 2)

    @given(text=SAFE_TEXT)
    @settings(max_examples=50)
    def test_ascii_never_mixed(self, text: str) -> None:
        assert not is_mixed_script(text)


# ---------------------------------------------------------------------------
# jinja2_escaper invariants
# ---------------------------------------------------------------------------


class TestJinja2EscaperProperties:
    """Property-based tests for jinja2_escaper."""

    @given(text=HOSTILE_TEXT)
    @settings(max_examples=50)
    def test_no_raw_delimiters(self, text: str) -> None:
        result = jinja2_escaper(text)
        assert not _JINJA2_DELIMITERS_RE.search(result)

    @given(text=SAFE_TEXT)
    @settings(max_examples=50)
    def test_safe_text_unchanged(self, text: str) -> None:
        if not _JINJA2_DELIMITERS_RE.search(text):
            assert jinja2_escaper(text) == text


# ---------------------------------------------------------------------------
# path_escaper invariants
# ---------------------------------------------------------------------------


class TestPathEscaperProperties:
    """Property-based tests for path_escaper."""

    @given(text=st.text(alphabet="abcdef/\\.0123456789", min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_no_leading_slash(self, text: str) -> None:
        assert not path_escaper(text).startswith("/")

    @given(text=st.text(alphabet="abcdef/\\.0123456789", min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_no_dotdot_segments(self, text: str) -> None:
        segments = path_escaper(text).split("/")
        assert ".." not in segments

    @given(text=st.text(alphabet="abcdef/\\.0123456789", min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_no_backslashes(self, text: str) -> None:
        assert "\\" not in path_escaper(text)

    @given(text=st.text(alphabet="abcdef/\\.0123456789", min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_idempotent(self, text: str) -> None:
        first = path_escaper(text)
        assert path_escaper(first) == first


# ---------------------------------------------------------------------------
# decode_evasion invariants
# ---------------------------------------------------------------------------


class TestDecodeEvasionProperties:
    """Property-based tests for decode_evasion."""

    @given(text=UNICODE_TEXT)
    @settings(max_examples=50)
    def test_never_raises(self, text: str) -> None:
        result = decode_evasion(text)
        assert isinstance(result, str)

    @given(text=SAFE_TEXT)
    @settings(max_examples=50)
    def test_clean_text_unchanged(self, text: str) -> None:
        if "%" not in text and "\\" not in text and "&" not in text:
            assert decode_evasion(text) == text
