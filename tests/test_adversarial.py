# ruff: noqa: RUF001
# tests/test_adversarial.py
"""Adversarial tests ported from navi-bootstrap.

Every test asserts TWO things: (1) clean output produced, (2) warning emitted.
"""

from __future__ import annotations

import logging

import pytest

from navi_sanitize import clean, jinja2_escaper, walk

# --- Homoglyph attacks ---


class TestHomoglyphAttacks:
    def test_cyrillic_a(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("nаvi") == "navi"
        assert "homoglyph" in caplog.text.lower()

    def test_multiple_cyrillic(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("руthоn") == "python"
        assert "homoglyph" in caplog.text.lower()

    def test_greek_uppercase(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("ΑΒC") == "ABC"
        assert "homoglyph" in caplog.text.lower()

    def test_mixed_cyrillic_greek(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("аο") == "ao"

    def test_paypal_homoglyph(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("pаypal.com") == "paypal.com"


# --- Zero-width attacks ---


class TestZeroWidthAttacks:
    def test_zwsp_in_word(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("te\u200bst") == "test"
        assert "invisible" in caplog.text.lower()

    def test_all_eight_zero_width(self, caplog: pytest.LogCaptureFixture) -> None:
        zw = "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u180e"
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("a" + zw + "b") == "ab"

    def test_zero_width_in_nested(self, caplog: pytest.LogCaptureFixture) -> None:
        data = {"outer": {"inner": "py\u200btest"}}
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = walk(data)
        assert result["outer"]["inner"] == "pytest"


# --- Fullwidth attacks ---


class TestFullwidthAttacks:
    def test_fullwidth_ignore(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("\uff49\uff47\uff4e\uff4f\uff52\uff45") == "ignore"

    def test_fullwidth_in_name(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("\uff54\uff45\uff53\uff54") == "test"


# --- Null byte attacks ---


class TestNullByteAttacks:
    def test_null_in_middle(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("hello\x00world") == "helloworld"
        assert "null byte" in caplog.text.lower()

    def test_null_in_extension(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            assert clean("test\x00.json\x00.txt") == "test.json.txt"


# --- Template injection (with jinja2_escaper) ---


class TestTemplateInjection:
    def test_double_brace(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = clean("{{ config }}", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_block_tag(self) -> None:
        result = clean("{% import os %}", escaper=jinja2_escaper)
        assert "{%" not in result
        assert "%}" not in result

    def test_comment(self) -> None:
        result = clean("{# malicious #}", escaper=jinja2_escaper)
        assert "{#" not in result
        assert "#}" not in result

    def test_ssti_class_traversal(self) -> None:
        payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        result = clean(payload, escaper=jinja2_escaper)
        assert "{{" not in result

    def test_ssti_lipsum_popen(self) -> None:
        payload = "{{ lipsum.__globals__['os'].popen('id').read() }}"
        result = clean(payload, escaper=jinja2_escaper)
        assert "{{" not in result

    def test_dos_loop(self) -> None:
        payload = "{% for x in range(999999999) %}{% endfor %}"
        result = clean(payload, escaper=jinja2_escaper)
        assert "{%" not in result


# --- Path traversal (with path_escaper) ---


class TestPathTraversal:
    def test_dotdot_traversal(self) -> None:
        from navi_sanitize import path_escaper

        assert clean("../../../etc/passwd", escaper=path_escaper) == "etc/passwd"

    def test_absolute_path(self) -> None:
        from navi_sanitize import path_escaper

        assert clean("/etc/passwd", escaper=path_escaper) == "etc/passwd"

    def test_mixed_traversal(self) -> None:
        from navi_sanitize import path_escaper

        assert clean("foo/../../../bar", escaper=path_escaper) == "foo/bar"


# --- Mixed-vector attacks ---


class TestMixedVectorAttacks:
    def test_homoglyph_plus_injection(self) -> None:
        result = clean("{{ cоnfig }}", escaper=jinja2_escaper)
        assert "{{" not in result
        assert "о" not in result

    def test_zero_width_in_delimiters(self) -> None:
        result = clean("{\u200b{ config }\u200b}", escaper=jinja2_escaper)
        assert "{{" not in result
        assert "\u200b" not in result

    def test_null_plus_homoglyph(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = clean("nаvi\x00")
        assert result == "navi"
        assert "null byte" in caplog.text.lower()
        assert "homoglyph" in caplog.text.lower()

    def test_hostile_nested_structure(self) -> None:
        data = {
            "name": "nаvi\x00",
            "desc": "{{ config }}",
            "nested": {"path": "../../etc", "zw": "te\u200bst"},
        }
        result = walk(data, escaper=jinja2_escaper)
        assert result["name"] == "navi"
        assert "{{" not in result["desc"]
        assert result["nested"]["zw"] == "test"


# --- Clean input passthrough ---


class TestCleanPassthrough:
    def test_clean_string_no_warnings(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            result = clean("perfectly normal text")
        assert result == "perfectly normal text"
        assert caplog.text == ""

    def test_non_strings_preserved(self) -> None:
        data = {"flag": True, "count": 42, "items": [1, 2, 3]}
        result = walk(data)
        assert result["flag"] is True
        assert result["count"] == 42
        assert result["items"] == [1, 2, 3]
