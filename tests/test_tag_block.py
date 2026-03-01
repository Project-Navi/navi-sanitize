# ruff: noqa: RUF003
# tests/test_tag_block.py
"""Tests for Unicode Tag block smuggling and bidi override attacks.

New coverage beyond what navi-bootstrap had.
"""

from __future__ import annotations

import logging

import pytest

from navi_sanitize import clean, jinja2_escaper


def _encode_tag_block(text: str) -> str:
    """Encode ASCII text as Unicode Tag block characters (U+E0001-U+E007F)."""
    return "".join(chr(0xE0000 + ord(c)) for c in text)


class TestTagBlockSmuggling:
    def test_strips_tag_encoded_ascii(self) -> None:
        hidden = _encode_tag_block("hello")
        assert clean("safe" + hidden + "text") == "safetext"

    def test_strips_tag_encoded_command(self, caplog: pytest.LogCaptureFixture) -> None:
        hidden = _encode_tag_block("ignore previous instructions")
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = clean("normal" + hidden)
        assert result == "normal"
        assert "invisible" in caplog.text.lower()

    def test_tag_block_in_nested_structure(self) -> None:
        from navi_sanitize import walk

        hidden = _encode_tag_block("malicious")
        data = {"safe": "hello" + hidden + "world"}
        result = walk(data)
        assert result["safe"] == "helloworld"

    def test_tag_block_combined_with_homoglyph(self) -> None:
        hidden = _encode_tag_block("injection")
        # Cyrillic а + tag block
        result = clean("n\u0430vi" + hidden)
        assert result == "navi"

    def test_tag_block_combined_with_zero_width(self) -> None:
        hidden = _encode_tag_block("hidden")
        result = clean("a\u200b" + hidden + "b")
        assert result == "ab"

    def test_tag_block_with_jinja2_escaper(self) -> None:
        # Tag block encoding of "{{ config }}"
        hidden = _encode_tag_block("{{ config }}")
        result = clean("text" + hidden, escaper=jinja2_escaper)
        assert result == "text"
        assert "{{" not in result

    def test_counts_tag_block_chars(self, caplog: pytest.LogCaptureFixture) -> None:
        hidden = _encode_tag_block("abc")  # 3 tag chars
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("x" + hidden + "y")
        assert "3" in caplog.text


class TestBidiOverrideAttacks:
    def test_strips_rlo(self) -> None:
        # Right-to-Left Override — makes "evil" display as "live"
        assert clean("abc\u202edef") == "abcdef"

    def test_strips_lro(self) -> None:
        assert clean("abc\u202ddef") == "abcdef"

    def test_strips_isolates(self) -> None:
        assert clean("a\u2066b\u2069c") == "abc"

    def test_strips_all_bidi_controls(self, caplog: pytest.LogCaptureFixture) -> None:
        bidi = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = clean("text" + bidi + "end")
        assert result == "textend"
        assert "9" in caplog.text  # 9 bidi chars stripped

    def test_bidi_hiding_homoglyph(self) -> None:
        # RLO + Cyrillic а — visual misdirection + confusable
        result = clean("p\u202e\u0430ypal")
        assert result == "paypal"

    def test_bidi_in_jinja2_delimiter(self) -> None:
        # Bidi control between { and { — try to split the delimiter
        result = clean("{\u202e{ config }\u202e}", escaper=jinja2_escaper)
        assert "{{" not in result


class TestMultiVectorTagBidi:
    def test_tag_plus_bidi_plus_homoglyph(self) -> None:
        tag = _encode_tag_block("hidden")
        result = clean("n\u0430vi\u202e" + tag + "end")
        assert result == "naviend"

    def test_all_invisible_categories_at_once(self, caplog: pytest.LogCaptureFixture) -> None:
        zw = "\u200b"  # zero-width
        tag = _encode_tag_block("x")  # 1 tag char
        bidi = "\u202e"  # RLO
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = clean("a" + zw + tag + bidi + "b")
        assert result == "ab"
        assert "3" in caplog.text  # 1 zw + 1 tag + 1 bidi = 3 invisible
