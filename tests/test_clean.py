# tests/test_clean.py
"""Tests for the clean() pipeline."""

from __future__ import annotations

import logging

import pytest


class TestNullByteRemoval:
    def test_strips_null_byte(self) -> None:
        from navi_sanitize import clean

        assert clean("hello\x00world") == "helloworld"

    def test_strips_multiple_null_bytes(self) -> None:
        from navi_sanitize import clean

        assert clean("\x00a\x00b\x00") == "ab"

    def test_warns_on_null_byte(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import clean

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("test\x00")
        assert "null byte" in caplog.text.lower()


class TestInvisibleStripping:
    def test_strips_zero_width_space(self) -> None:
        from navi_sanitize import clean

        assert clean("te\u200bst") == "test"

    def test_strips_all_zero_width_chars(self) -> None:
        from navi_sanitize import clean

        zw = "\u200b\u200c\u200d\u2060\ufeff\u180e"
        assert clean("a" + zw + "b") == "ab"

    def test_strips_tag_block_chars(self) -> None:
        from navi_sanitize import clean

        # Tag block: U+E0001 through U+E007F encode invisible ASCII
        tag_hello = "".join(chr(0xE0000 + ord(c)) for c in "hello")
        assert clean("safe" + tag_hello + "text") == "safetext"

    def test_strips_bidi_overrides(self) -> None:
        from navi_sanitize import clean

        assert clean("abc\u202edef") == "abcdef"

    def test_strips_bidi_isolates(self) -> None:
        from navi_sanitize import clean

        assert clean("abc\u2066def\u2069ghi") == "abcdefghi"

    def test_warns_on_invisible(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import clean

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("te\u200bst")
        assert "invisible" in caplog.text.lower()

    def test_warns_with_count(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import clean

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("a\u200b\u200c\u200db")
        assert "3" in caplog.text


class TestNFKCNormalization:
    def test_normalizes_fullwidth(self) -> None:
        from navi_sanitize import clean

        assert clean("\uff54\uff45\uff53\uff54") == "test"

    def test_warns_on_fullwidth(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import clean

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("\uff54est")
        assert "fullwidth" in caplog.text.lower() or "normalized" in caplog.text.lower()


class TestHomoglyphReplacement:
    def test_replaces_cyrillic_a(self) -> None:
        from navi_sanitize import clean

        assert clean("n\u0430vi") == "navi"

    def test_replaces_greek_uppercase(self) -> None:
        from navi_sanitize import clean

        assert clean("\u0391\u0392C") == "ABC"

    def test_replaces_typographic_dashes(self) -> None:
        from navi_sanitize import clean

        assert clean("a\u2013b\u2014c") == "a-b-c"

    def test_replaces_smart_quotes(self) -> None:
        from navi_sanitize import clean

        assert clean("\u201chello\u201d") == '"hello"'

    def test_warns_with_count(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import clean

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("\u0430\u0435\u043e")
        assert "3" in caplog.text
        assert "homoglyph" in caplog.text.lower()


class TestCleanPassthrough:
    def test_clean_text_unchanged(self) -> None:
        from navi_sanitize import clean

        assert clean("hello world") == "hello world"

    def test_no_warnings_on_clean_text(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import clean

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("perfectly normal text")
        assert caplog.text == ""

    def test_empty_string(self) -> None:
        from navi_sanitize import clean

        assert clean("") == ""


class TestEscaperIntegration:
    def test_escaper_runs_after_universal_stages(self) -> None:
        from navi_sanitize import clean

        def upper_escaper(s: str) -> str:
            return s.upper()

        # Homoglyph replacement first, then escaper
        assert clean("n\u0430vi", escaper=upper_escaper) == "NAVI"

    def test_no_escaper_skips_stage_5(self) -> None:
        from navi_sanitize import clean

        assert clean("{{ config }}") == "{{ config }}"

    def test_escaper_receives_clean_text(self) -> None:
        from navi_sanitize import clean

        received: list[str] = []

        def spy_escaper(s: str) -> str:
            received.append(s)
            return s

        clean("n\u0430vi\x00", escaper=spy_escaper)
        assert received == ["navi"]  # null byte and homoglyph already cleaned
