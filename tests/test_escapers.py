# tests/test_escapers.py
"""Tests for built-in escapers."""

from __future__ import annotations


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
