# ruff: noqa: RUF001, RUF003
"""Unreasonable garbage inputs — find what breaks."""

from __future__ import annotations

import logging
import sys

import pytest

from navi_sanitize import clean, jinja2_escaper, path_escaper, walk

# --- Strings made entirely of hostile characters ---


class TestPureGarbage:
    def test_string_of_only_null_bytes(self) -> None:
        assert clean("\x00" * 10000) == ""

    def test_string_of_only_zero_width(self) -> None:
        assert clean("\u200b" * 10000) == ""

    def test_string_of_only_bidi(self) -> None:
        bidi = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
        assert clean(bidi * 1000) == ""

    def test_string_of_only_tag_block(self) -> None:
        tag = "".join(chr(0xE0000 + ord(c)) for c in "AAAA")
        assert clean(tag * 2500) == ""

    def test_string_of_only_homoglyphs(self) -> None:
        # All Cyrillic lookalikes — should all become Latin
        cyrillic = "аеорсухАВЕКМНОРСТХ"
        result = clean(cyrillic)
        assert all(ord(c) < 128 for c in result)

    def test_every_invisible_category_interleaved(self) -> None:
        null = "\x00"
        zw = "\u200b"
        tag = chr(0xE0061)  # tag 'a'
        bidi = "\u202e"
        chunk = null + zw + tag + bidi
        result = clean("X" + chunk * 5000 + "Y")
        assert result == "XY"


# --- Size extremes ---


class TestSizeExtremes:
    def test_1mb_clean_string(self) -> None:
        big = "a" * (1024 * 1024)
        assert clean(big) == big

    def test_1mb_hostile_string(self) -> None:
        big = ("n\u0430vi\x00\u200b" * 100000)[: 1024 * 1024]
        result = clean(big)
        assert "\x00" not in result
        assert "\u200b" not in result
        assert "\u0430" not in result

    def test_empty_string(self) -> None:
        assert clean("") == ""

    def test_single_char(self) -> None:
        assert clean("a") == "a"

    def test_single_null(self) -> None:
        assert clean("\x00") == ""

    def test_single_homoglyph(self) -> None:
        assert clean("\u0430") == "a"

    def test_deeply_nested_walk(self) -> None:
        """100 levels deep — will deepcopy/recursion handle it?"""
        data: object = "n\u0430vi"
        for _ in range(100):
            data = {"inner": data}
        result = walk(data)
        # Dig down 100 levels
        node = result
        for _ in range(100):
            assert isinstance(node, dict)
            node = node["inner"]
        assert node == "navi"

    def test_wide_dict_walk(self) -> None:
        """10,000 keys."""
        data = {f"key_{i}": f"val\x00{i}" for i in range(10000)}
        result = walk(data)
        assert all("\x00" not in v for v in result.values() if isinstance(v, str))

    def test_wide_list_walk(self) -> None:
        """10,000 items."""
        data = [f"val\u0430{i}" for i in range(10000)]
        result = walk(data)
        assert all("\u0430" not in v for v in result)


# --- Unicode edge cases ---


class TestUnicodeEdgeCases:
    def test_emoji_passthrough(self) -> None:
        assert clean("hello 🎉🔥💀") == "hello 🎉🔥💀"

    def test_combining_characters(self) -> None:
        # e + combining acute accent — NFKC may compose this
        composed = clean("e\u0301")
        # NFKC should compose to é
        assert composed == "\u00e9"

    def test_hangul_passthrough(self) -> None:
        assert clean("안녕하세요") == "안녕하세요"

    def test_cjk_passthrough(self) -> None:
        assert clean("漢字テスト") == "漢字テスト"

    def test_arabic_passthrough(self) -> None:
        # Arabic text without bidi controls should pass through
        assert clean("مرحبا") == "مرحبا"

    def test_max_codepoint(self) -> None:
        # U+10FFFF — max Unicode codepoint
        assert clean("a\U0010ffffb") == "a\U0010ffffb"

    def test_tag_block_boundary(self) -> None:
        # U+E0000 is now IN the tag block range — should be stripped
        # U+E0080 is just OUTSIDE — should pass through
        after_tag = chr(0xE0080)
        result = clean("a" + chr(0xE0000) + "b" + after_tag + "c")
        assert result == "ab" + after_tag + "c"

    def test_fullwidth_digits(self) -> None:
        assert clean("\uff10\uff11\uff12\uff13") == "0123"

    def test_fullwidth_jinja_delimiters(self) -> None:
        # Fullwidth {{ — NFKC normalizes to regular {{ then escaper catches it
        fullwidth_open = "\uff5b\uff5b"  # ｛｛
        fullwidth_close = "\uff5d\uff5d"  # ｝｝
        result = clean(fullwidth_open + " config " + fullwidth_close, escaper=jinja2_escaper)
        assert "{{" not in result

    def test_nfkc_superscript_collapse(self) -> None:
        # Superscript digits → regular digits under NFKC
        assert clean("\u00b2\u00b3") == "23"  # ² ³

    def test_nfkc_ligature_expansion(self) -> None:
        # ﬁ ligature → "fi" under NFKC
        assert clean("\ufb01le") == "file"

    def test_repeated_nfkc_is_stable(self) -> None:
        """Applying clean twice should give same result."""
        hostile = "n\u0430vi\x00\u200b\uff54est"
        first = clean(hostile)
        second = clean(first)
        assert first == second


# --- Escaper abuse ---


class TestEscaperAbuse:
    def test_escaper_that_raises(self) -> None:
        def bomb(s: str) -> str:
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            clean("hello", escaper=bomb)

    def test_escaper_that_returns_empty(self) -> None:
        assert clean("hello", escaper=lambda s: "") == ""

    def test_escaper_that_doubles(self) -> None:
        assert clean("hi", escaper=lambda s: s + s) == "hihi"

    def test_escaper_that_adds_hostile_chars(self) -> None:
        """Escaper injects garbage — pipeline doesn't re-run."""

        def evil_escaper(s: str) -> str:
            return s + "\x00\u200b\u0430"

        result = clean("hello", escaper=evil_escaper)
        # The escaper runs AFTER the pipeline — its output is NOT re-sanitized
        assert "\x00" in result  # this is by design

    def test_escaper_with_none_input_from_empty(self) -> None:
        """Escaper receives empty string after all content stripped."""
        received: list[str] = []

        def spy(s: str) -> str:
            received.append(s)
            return s

        clean("\x00\u200b", escaper=spy)
        assert received == [""]

    def test_both_escapers_sequentially(self) -> None:
        """Apply path then jinja — user composes their own."""

        def combined(s: str) -> str:
            return jinja2_escaper(path_escaper(s))

        result = clean("../../{{ config }}", escaper=combined)
        assert ".." not in result
        assert "{{" not in result


# --- walk() type edge cases ---


class TestWalkTypeEdgeCases:
    def test_walk_tuple(self) -> None:
        """Tuples are not lists — should pass through unchanged."""
        data = ("n\u0430vi", "test")
        result = walk(data)
        # Tuple is not dict/list/str — passes through as-is (via deepcopy)
        assert result == data

    def test_walk_set(self) -> None:
        data = {"n\u0430vi", "test"}
        result = walk(data)
        assert result == data  # set not traversed

    def test_walk_nested_with_tuples(self) -> None:
        data = {"key": ("n\u0430vi", ["\x00test"])}
        result = walk(data)
        # Tuple passes through, list inside tuple — tuple is not traversed
        assert result["key"] == ("n\u0430vi", ["\x00test"])

    def test_walk_int(self) -> None:
        assert walk(42) == 42

    def test_walk_float(self) -> None:
        assert walk(3.14) == 3.14

    def test_walk_none(self) -> None:
        assert walk(None) is None

    def test_walk_bool(self) -> None:
        assert walk(True) is True

    def test_walk_bytes(self) -> None:
        """bytes is not str — should pass through."""
        data = b"hello\x00world"
        result = walk(data)
        assert result == data

    def test_walk_dict_with_non_string_keys(self) -> None:
        data = {1: "n\u0430vi", (2, 3): "te\x00st"}
        result = walk(data)
        assert result[1] == "navi"
        assert result[(2, 3)] == "test"

    def test_walk_mixed_value_types(self) -> None:
        data = {
            "str": "n\u0430vi",
            "int": 42,
            "float": 3.14,
            "bool": True,
            "none": None,
            "bytes": b"raw",
            "list": ["te\x00st", 1, None],
            "dict": {"nested": "v\u0430lue"},
        }
        result = walk(data)
        assert result["str"] == "navi"
        assert result["int"] == 42
        assert result["float"] == 3.14
        assert result["bool"] is True
        assert result["none"] is None
        assert result["bytes"] == b"raw"
        assert result["list"] == ["test", 1, None]
        assert result["dict"]["nested"] == "value"


# --- Multi-vector compound attacks ---


class TestCompoundAttacks:
    def test_every_attack_in_one_string(self) -> None:
        """Null + zero-width + tag + bidi + fullwidth + homoglyph + SSTI."""
        tag_block = "".join(chr(0xE0000 + ord(c)) for c in "pwned")
        attack = (
            "\x00"  # null
            "n\u0430vi"  # homoglyph
            "\u200b"  # zero-width
            + tag_block  # tag block
            + "\u202e"  # bidi
            "\uff54\uff45\uff53\uff54"  # fullwidth "test"
            "{{ evil }}"  # SSTI
        )
        result = clean(attack, escaper=jinja2_escaper)
        assert "\x00" not in result
        assert "\u0430" not in result
        assert "\u200b" not in result
        assert "\u202e" not in result
        assert "{{" not in result
        # Should contain "navi" and "test" in Latin
        assert "navi" in result
        assert "test" in result

    def test_hostile_walk_with_every_type(self) -> None:
        data = {
            "users": [
                {
                    "name": "n\u0430vi\x00",
                    "bio": "{{ lipsum.__globals__ }}",
                    "path": "../../etc/passwd",
                    "tags": ["z\u200bero", "\uff46ullwidth"],
                    "active": True,
                    "score": 42.5,
                    "avatar": None,
                }
                for _ in range(50)
            ]
        }
        result = walk(data, escaper=jinja2_escaper)
        for user in result["users"]:
            assert user["name"] == "navi"
            assert "{{" not in user["bio"]
            assert "\u200b" not in user["tags"][0]
            assert user["tags"][1] == "fullwidth"
            assert user["active"] is True
            assert user["score"] == 42.5
            assert user["avatar"] is None


# --- Logging edge cases ---


class TestLoggingEdgeCases:
    def test_no_duplicate_warnings_on_clean_input(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            for _ in range(100):
                clean("perfectly safe")
        assert caplog.text == ""

    def test_warnings_dont_accumulate_across_calls(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("n\u0430vi")
        first_count = caplog.text.count("homoglyph")
        assert first_count == 1

    def test_all_warning_types_in_one_call(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("\x00\u200bn\u0430vi\uff54")
        text = caplog.text.lower()
        assert "null byte" in text
        assert "invisible" in text
        assert "homoglyph" in text
        assert "fullwidth" in text or "normalized" in text


# --- Recursion depth ---


class TestRecursionLimits:
    def test_recursion_near_limit(self) -> None:
        """Build a structure near Python's recursion limit."""
        depth = min(sys.getrecursionlimit() // 4, 250)
        data: object = "n\u0430vi"
        for _ in range(depth):
            data = [data]
        result = walk(data)
        node = result
        for _ in range(depth):
            assert isinstance(node, list)
            node = node[0]
        assert node == "navi"
