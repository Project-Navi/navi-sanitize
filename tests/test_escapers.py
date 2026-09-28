# tests/test_escapers.py
"""Tests for built-in escapers."""

from __future__ import annotations

import itertools
import re

import pytest

_JINJA2_DELIMITER_RE = re.compile(r"\{\{|\}\}|\{%|%\}|\{#|#\}")
# The pre-0.2.2 jinja2_escaper pattern, kept as a differential oracle.
_LEGACY_JINJA2_RE = re.compile(r"\{{2,}|\}{2,}|\{%|%\}|\{#|#\}")


def _legacy_jinja2_escaper(text: str) -> str:
    return _LEGACY_JINJA2_RE.sub(lambda m: "".join("\\" + c for c in m.group()), text)


class TestJinja2Escaper:
    def test_escapes_double_braces(self) -> None:
        from navi_sanitize import jinja2_escaper

        result = jinja2_escaper("{{ config }}")
        assert "{{" not in result

    def test_escapes_block_tags(self) -> None:
        from navi_sanitize import jinja2_escaper

        result = jinja2_escaper("{% import os %}")
        assert "{%" not in result
        assert "%}" not in result

    def test_escapes_comments(self) -> None:
        from navi_sanitize import jinja2_escaper

        result = jinja2_escaper("{# comment #}")
        assert "{#" not in result
        assert "#}" not in result

    def test_clean_text_unchanged(self) -> None:
        from navi_sanitize import jinja2_escaper

        assert jinja2_escaper("hello world") == "hello world"

    def test_ssti_payload(self) -> None:
        from navi_sanitize import jinja2_escaper

        payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        result = jinja2_escaper(payload)
        assert "{{" not in result

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("{{%", "\\{\\{\\%"),
            ("{{#", "\\{\\{\\#"),
            ("{%}", "\\{\\%\\}"),
            ("{#}", "\\{\\#\\}"),
            ("%}}", "\\%\\}\\}"),
            ("#}}", "\\#\\}\\}"),
            ("{{% x %}}", "\\{\\{\\% x \\%\\}\\}"),
        ],
    )
    def test_overlapping_delimiters_fully_escaped(self, text: str, expected: str) -> None:
        """A delimiter overlapping an escaped run must not survive (NS-09)."""
        from navi_sanitize import jinja2_escaper

        result = jinja2_escaper(text)
        assert result == expected
        assert not _JINJA2_DELIMITER_RE.search(result)
        assert jinja2_escaper(result) == result

    def test_exhaustive_short_inputs(self) -> None:
        """No raw delimiter, idempotent, and unchanged wherever the old output was sound."""
        from navi_sanitize import jinja2_escaper

        for n in range(1, 7):
            for chars in itertools.product("{}%#x\\", repeat=n):
                text = "".join(chars)
                result = jinja2_escaper(text)
                assert not _JINJA2_DELIMITER_RE.search(result), text
                assert jinja2_escaper(result) == result, text
                legacy = _legacy_jinja2_escaper(text)
                if not _JINJA2_DELIMITER_RE.search(legacy):
                    assert result == legacy, text

    def test_other_delimiter_configurations_not_handled(self) -> None:
        """Only Jinja2's default delimiters are edited; custom syntax passes through."""
        from navi_sanitize import jinja2_escaper

        assert jinja2_escaper("<% x %> ${ y }") == "<% x %> ${ y }"


class TestPathEscaper:
    def test_strips_dotdot(self) -> None:
        from navi_sanitize import path_escaper

        assert path_escaper("../../etc/passwd") == "etc/passwd"

    def test_strips_leading_slash(self) -> None:
        from navi_sanitize import path_escaper

        assert path_escaper("/etc/passwd") == "etc/passwd"

    def test_strips_dot_segments(self) -> None:
        from navi_sanitize import path_escaper

        assert path_escaper("foo/./bar/../baz") == "foo/bar/baz"

    def test_clean_path_unchanged(self) -> None:
        from navi_sanitize import path_escaper

        assert path_escaper("src/main.py") == "src/main.py"

    def test_empty_string(self) -> None:
        from navi_sanitize import path_escaper

        assert path_escaper("") == ""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("...", ""),
            (".../file", "file"),
            ("...../file", "file"),
            ("a/.../b", "a/b"),
            ("a\\...\\b", "a/b"),
            ("..../x", "x"),
        ],
    )
    def test_embedded_dotdot_removal_cannot_leave_dot_segment(
        self, text: str, expected: str
    ) -> None:
        """Deleting '..' inside a segment must not create a new '.' segment (NS-01)."""
        from navi_sanitize import clean, path_escaper

        assert path_escaper(text) == expected
        assert path_escaper(expected) == expected
        assert clean(text, escaper=path_escaper) == expected

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("file..txt", "filetxt"),
            ("..hidden", "hidden"),
            (".hidden", ".hidden"),
            ("a/.b/c.", "a/.b/c."),
            ("//server/share", "server/share"),
            ("C:/temp/file", "C:/temp/file"),
            ("C:\\temp\\file", "C:/temp/file"),
        ],
    )
    def test_existing_lexical_policy_preserved(self, text: str, expected: str) -> None:
        """Embedded '..' deletion and lexical-only handling stay as before."""
        from navi_sanitize import path_escaper

        assert path_escaper(text) == expected

    def test_exhaustive_short_inputs(self) -> None:
        """Every output is free of '.'/'..'/empty segments and is a fixed point."""
        from navi_sanitize import path_escaper

        for n in range(1, 8):
            for chars in itertools.product("./\\a", repeat=n):
                text = "".join(chars)
                result = path_escaper(text)
                if result:
                    segments = result.split("/")
                    assert "" not in segments, text
                    assert "." not in segments, text
                    assert ".." not in segments, text
                assert "\\" not in result, text
                assert path_escaper(result) == result, text

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("a/\u2026/b", "a/b"),  # HORIZONTAL ELLIPSIS -> "..." under NFKC
            ("\u2025/etc", "etc"),  # TWO DOT LEADER -> ".."
            ("\uff0e\uff0e/etc", "etc"),  # fullwidth full stops
        ],
    )
    def test_nfkc_produced_dots_with_clean(self, text: str, expected: str) -> None:
        from navi_sanitize import clean, path_escaper

        assert clean(text, escaper=path_escaper) == expected


class TestEscapersWithClean:
    def test_clean_with_jinja2_escaper(self) -> None:
        from navi_sanitize import clean, jinja2_escaper

        result = clean("{{ config }}", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_clean_with_path_escaper(self) -> None:
        from navi_sanitize import clean, path_escaper

        result = clean("../../etc/passwd", escaper=path_escaper)
        assert result == "etc/passwd"

    def test_pipeline_then_escaper(self) -> None:
        from navi_sanitize import clean, jinja2_escaper

        # Zero-width chars between delimiters + homoglyph
        result = clean("{\u200b{ c\u043enfig }\u200b}", escaper=jinja2_escaper)
        assert "{{" not in result
        assert "\u200b" not in result
        assert "\u043e" not in result
