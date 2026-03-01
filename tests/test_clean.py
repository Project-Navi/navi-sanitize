# tests/test_clean.py
"""Tests for the clean() pipeline."""

from __future__ import annotations


class TestNullByteRemoval:
    def test_strips_null_byte(self) -> None:
        from navi_sanitize import clean

        assert clean("hello\x00world") == "helloworld"

    def test_no_change_on_clean_input(self) -> None:
        from navi_sanitize import clean

        assert clean("hello") == "hello"
