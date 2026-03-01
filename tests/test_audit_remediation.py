# ruff: noqa: RUF001, RUF002
"""Regression tests for adversarial audit remediation.

Each test class maps to a specific audit finding.
A PASSING test means the fix is working.
"""

from __future__ import annotations

import logging

import pytest

from navi_sanitize import clean, jinja2_escaper, path_escaper, walk

# =============================================================================
# CRITICAL: Supplementary Variation Selectors (U+E0100-U+E01EF)
# =============================================================================


class TestSupplementaryVariationSelectors:
    """VS17-VS256 are invisible modifiers that must be stripped."""

    def test_vs17_stripped(self) -> None:
        result = clean("test\U000e0100ing")
        assert result == "testing", f"VS17 (U+E0100) survived: {result!r}"

    def test_vs256_stripped(self) -> None:
        result = clean("test\U000e01efing")
        assert result == "testing", f"VS256 (U+E01EF) survived: {result!r}"

    def test_midrange_vs_stripped(self) -> None:
        result = clean("a\U000e0150b")
        assert result == "ab", f"VS mid-range survived: {result!r}"

    def test_multiple_supplement_vs(self) -> None:
        vs = "\U000e0100\U000e0110\U000e0120"
        result = clean("x" + vs + "y")
        assert result == "xy"


# =============================================================================
# CRITICAL: U+E0000 (LANGUAGE TAG) now stripped
# =============================================================================


class TestLanguageTag:
    """U+E0000 was not stripped before; now included in TAG_BLOCK_RANGE."""

    def test_language_tag_stripped(self) -> None:
        result = clean("a\U000e0000b")
        assert result == "ab", f"U+E0000 LANGUAGE TAG survived: {result!r}"

    def test_tag_block_full_range(self) -> None:
        # U+E0000 through U+E007F should all be stripped
        tag_chars = "".join(chr(c) for c in range(0xE0000, 0xE0080))
        result = clean("start" + tag_chars + "end")
        assert result == "startend"


# =============================================================================
# LRM / RLM zero-width directional marks
# =============================================================================


class TestDirectionalMarks:
    """U+200E (LRM) and U+200F (RLM) are zero-width and must be stripped."""

    def test_lrm_stripped(self) -> None:
        result = clean("admin\u200eistrator")
        assert result == "administrator", f"LRM survived: {result!r}"

    def test_rlm_stripped(self) -> None:
        result = clean("admin\u200fistrator")
        assert result == "administrator", f"RLM survived: {result!r}"

    def test_lrm_rlm_between_delimiters(self) -> None:
        result = clean("{\u200e{ config }\u200f}", escaper=jinja2_escaper)
        assert "{{" not in result


# =============================================================================
# Greek lowercase homoglyphs (iota, nu, rho)
# =============================================================================


class TestGreekLowercaseHomoglyphs:
    """Greek ι→i, ν→v, ρ→p are high-confidence confusables."""

    def test_greek_iota(self) -> None:
        result = clean("adm\u03b9n")
        assert result == "admin", f"Greek ι survived: {result!r}"

    def test_greek_nu(self) -> None:
        result = clean("na\u03bdi")
        assert result == "navi", f"Greek ν survived: {result!r}"

    def test_greek_rho(self) -> None:
        result = clean("\u03c1assword")
        assert result == "password", f"Greek ρ survived: {result!r}"

    def test_mixed_greek_latin(self) -> None:
        # All three in one string
        result = clean("\u03c1a\u03b9\u03bd")
        assert result == "paiv"


# =============================================================================
# Cyrillic Shha and uppercase additions (test coverage gaps)
# =============================================================================


class TestCyrillicTestCoverage:
    """Homoglyph map entries that lacked dedicated tests."""

    def test_cyrillic_shha(self) -> None:
        result = clean("\u04bbell")
        assert result == "hell", f"Cyrillic һ survived: {result!r}"

    def test_cyrillic_uppercase_i(self) -> None:
        result = clean("\u0406nput")
        assert result == "Input", f"Cyrillic І survived: {result!r}"

    def test_cyrillic_uppercase_s(self) -> None:
        result = clean("\u0405ystem")
        assert result == "System", f"Cyrillic Ѕ survived: {result!r}"

    def test_cyrillic_uppercase_j(self) -> None:
        result = clean("\u0408ava")
        assert result == "Java", f"Cyrillic Ј survived: {result!r}"


# =============================================================================
# Path escaper backslash traversal fix
# =============================================================================


class TestPathBackslashTraversal:
    """Backslashes are now normalized to / before processing."""

    def test_backslash_traversal_blocked(self) -> None:
        result = clean("..\\..\\etc\\passwd", escaper=path_escaper)
        assert ".." not in result
        assert result == "etc/passwd"

    def test_mixed_separator_traversal(self) -> None:
        result = clean("../..\\../etc/passwd", escaper=path_escaper)
        assert ".." not in result

    def test_backslash_only_path(self) -> None:
        result = clean("foo\\bar\\baz", escaper=path_escaper)
        assert result == "foo/bar/baz"

    def test_leading_backslash_stripped(self) -> None:
        result = clean("\\etc\\passwd", escaper=path_escaper)
        assert not result.startswith("/")
        assert not result.startswith("\\")


# =============================================================================
# walk() dict key sanitization
# =============================================================================


class TestWalkDictKeySanitization:
    """walk() now sanitizes string dict keys."""

    def test_homoglyph_in_key(self) -> None:
        data = {"n\u0430me": "value"}
        result = walk(data)
        assert "name" in result
        assert "n\u0430me" not in result

    def test_null_byte_in_key(self) -> None:
        data = {"ke\x00y": "value"}
        result = walk(data)
        assert "key" in result

    def test_jinja_in_key_with_escaper(self) -> None:
        data = {"{{ config }}": "value"}
        result = walk(data, escaper=jinja2_escaper)
        assert "{{ config }}" not in result

    def test_non_string_keys_unchanged(self) -> None:
        data = {1: "val", (2, 3): "val2"}
        result = walk(data)
        assert result[1] == "val"
        assert result[(2, 3)] == "val2"

    def test_key_collision_last_wins(self) -> None:
        # Two keys that normalize to the same ASCII
        data = {"n\u0430me": "cyrillic", "name": "latin"}
        result = walk(data)
        assert "name" in result
        # One of the values should win (dict ordering)
        assert result["name"] in ("cyrillic", "latin")


# =============================================================================
# clean() type enforcement
# =============================================================================


class TestCleanTypeEnforcement:
    """clean() must raise TypeError for non-string input."""

    def test_none_raises(self) -> None:
        with pytest.raises(TypeError, match="got NoneType"):
            clean(None)  # type: ignore[arg-type]

    def test_int_raises(self) -> None:
        with pytest.raises(TypeError, match="got int"):
            clean(42)  # type: ignore[arg-type]

    def test_bytes_raises(self) -> None:
        with pytest.raises(TypeError, match="got bytes"):
            clean(b"hello")  # type: ignore[arg-type]

    def test_list_raises(self) -> None:
        with pytest.raises(TypeError, match="got list"):
            clean(["hello"])  # type: ignore[arg-type]


# =============================================================================
# Escaper return type validation
# =============================================================================


class TestEscaperReturnTypeValidation:
    """Escaper that returns non-str must raise TypeError."""

    def test_escaper_returns_none(self) -> None:
        with pytest.raises(TypeError, match="got NoneType"):
            clean("hello", escaper=lambda s: None)  # type: ignore[arg-type,return-value]

    def test_escaper_returns_int(self) -> None:
        with pytest.raises(TypeError, match="got int"):
            clean("hello", escaper=lambda s: 42)  # type: ignore[arg-type,return-value]

    def test_escaper_returns_str_ok(self) -> None:
        result = clean("hello", escaper=lambda s: s.upper())
        assert result == "HELLO"


# =============================================================================
# Null byte warning count
# =============================================================================


class TestNullByteWarningCount:
    """Warning must include count per project convention."""

    def test_single_null_byte_count(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("test\x00")
        assert "1 null byte" in caplog.text

    def test_multiple_null_byte_count(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            clean("\x00a\x00b\x00")
        assert "3 null byte" in caplog.text


# =============================================================================
# Idempotency with escapers
# =============================================================================


class TestIdempotencyWithEscapers:
    """clean(clean(x, escaper=e), escaper=e) == clean(x, escaper=e)."""

    def test_idempotent_with_jinja2_escaper(self) -> None:
        inputs = [
            "{{ config }}",
            "{{{ triple }}}",
            "{% for x in items %}{% endfor %}",
            "{# comment #}",
            "normal text",
        ]
        for inp in inputs:
            first = clean(inp, escaper=jinja2_escaper)
            second = clean(first, escaper=jinja2_escaper)
            assert first == second, f"Not idempotent with jinja2 for {inp!r}"

    def test_idempotent_with_path_escaper(self) -> None:
        inputs = [
            "../../etc/passwd",
            "/root/.ssh/id_rsa",
            "foo/../bar",
            "..\\..\\windows\\system32",
        ]
        for inp in inputs:
            first = clean(inp, escaper=path_escaper)
            second = clean(first, escaper=path_escaper)
            assert first == second, f"Not idempotent with path for {inp!r}"


# =============================================================================
# Jinja2 whitespace control variants
# =============================================================================


class TestJinja2WhitespaceControl:
    """Whitespace control delimiters {%- -%} must be escaped."""

    def test_block_strip_open(self) -> None:
        result = clean("{%- for x in items -%}", escaper=jinja2_escaper)
        assert "{%" not in result

    def test_block_preserve_open(self) -> None:
        result = clean("{%+ for x in items +%}", escaper=jinja2_escaper)
        assert "{%" not in result

    def test_single_brace_passthrough(self) -> None:
        assert jinja2_escaper("{ config }") == "{ config }"


# =============================================================================
# NFKC presentation form braces
# =============================================================================


class TestNFKCPresentationFormBraces:
    """Small form and vertical form braces normalize to ASCII under NFKC."""

    def test_small_form_braces(self) -> None:
        # U+FE5B/FE5C — small left/right curly bracket
        result = clean("\ufe5b\ufe5b config \ufe5c\ufe5c", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_vertical_form_braces(self) -> None:
        # U+FE37/FE38 — vertical left/right curly bracket
        result = clean("\ufe37\ufe37 config \ufe38\ufe38", escaper=jinja2_escaper)
        assert "{{" not in result


# =============================================================================
# Public API contract
# =============================================================================


class TestPublicAPIContract:
    """Verify exports, version, and __all__."""

    def test_public_exports(self) -> None:
        import navi_sanitize

        assert hasattr(navi_sanitize, "__version__")
        assert set(navi_sanitize.__all__) == {
            "clean",
            "decode_evasion",
            "detect_scripts",
            "is_mixed_script",
            "walk",
            "jinja2_escaper",
            "path_escaper",
            "Escaper",
        }

    def test_replacement_character_passthrough(self) -> None:
        assert clean("hello\ufffdworld") == "hello\ufffdworld"
