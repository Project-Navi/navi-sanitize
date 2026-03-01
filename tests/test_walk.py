# tests/test_walk.py
"""Tests for the walk() recursive sanitizer."""

from __future__ import annotations

import logging

import pytest


class TestWalkDict:
    def test_sanitizes_string_values(self) -> None:
        from navi_sanitize import walk

        data = {"name": "n\u0430vi", "count": 42}
        result = walk(data)
        assert result["name"] == "navi"
        assert result["count"] == 42

    def test_deep_copy(self) -> None:
        from navi_sanitize import walk

        data = {"name": "n\u0430vi"}
        result = walk(data)
        assert result is not data
        assert data["name"] == "n\u0430vi"  # original unchanged

    def test_nested_dicts(self) -> None:
        from navi_sanitize import walk

        data = {"outer": {"inner": "te\x00st"}}
        result = walk(data)
        assert result["outer"]["inner"] == "test"

    def test_preserves_non_strings(self) -> None:
        from navi_sanitize import walk

        data = {"flag": True, "count": 42, "ratio": 3.14, "empty": None}
        result = walk(data)
        assert result == data


class TestWalkList:
    def test_sanitizes_list_strings(self) -> None:
        from navi_sanitize import walk

        data = ["n\u0430vi", "te\x00st"]
        result = walk(data)
        assert result == ["navi", "test"]

    def test_nested_lists(self) -> None:
        from navi_sanitize import walk

        data = [["n\u0430vi"], ["te\x00st"]]
        result = walk(data)
        assert result == [["navi"], ["test"]]


class TestWalkMixed:
    def test_dict_with_list_values(self) -> None:
        from navi_sanitize import walk

        data = {"names": ["n\u0430vi", "hello"], "count": 3}
        result = walk(data)
        assert result["names"] == ["navi", "hello"]
        assert result["count"] == 3

    def test_list_of_dicts(self) -> None:
        from navi_sanitize import walk

        data = [{"name": "te\x00st"}, {"name": "hello"}]
        result = walk(data)
        assert result[0]["name"] == "test"
        assert result[1]["name"] == "hello"


class TestWalkWithEscaper:
    def test_escaper_applied_to_all_strings(self) -> None:
        from navi_sanitize import jinja2_escaper, walk

        data = {"a": "{{ x }}", "b": "safe", "c": ["{{ y }}"]}
        result = walk(data, escaper=jinja2_escaper)
        assert "{{" not in result["a"]
        assert result["b"] == "safe"
        assert "{{" not in result["c"][0]


class TestWalkEdgeCases:
    def test_empty_dict(self) -> None:
        from navi_sanitize import walk

        assert walk({}) == {}

    def test_empty_list(self) -> None:
        from navi_sanitize import walk

        assert walk([]) == []

    def test_plain_string(self) -> None:
        from navi_sanitize import walk

        assert walk("n\u0430vi") == "navi"

    def test_non_string_scalar(self) -> None:
        from navi_sanitize import walk

        assert walk(42) == 42

    def test_warns_on_hostile_values(self, caplog: pytest.LogCaptureFixture) -> None:
        from navi_sanitize import walk

        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            walk({"name": "n\u0430vi\x00"})
        assert "homoglyph" in caplog.text.lower()
        assert "null byte" in caplog.text.lower()
