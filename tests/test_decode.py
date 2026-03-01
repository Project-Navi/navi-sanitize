# SPDX-License-Identifier: MIT
"""Tests for multi-encoding evasion decode."""

from __future__ import annotations

import logging

import pytest

from navi_sanitize import clean, decode_evasion, path_escaper


class TestDecodeSingleLayer:
    """Single-layer decode tests."""

    def test_url_encoding(self) -> None:
        assert decode_evasion("%2e%2e%2f") == "../"

    def test_html_entities(self) -> None:
        assert decode_evasion("&lt;script&gt;") == "<script>"

    def test_hex_escapes(self) -> None:
        assert decode_evasion("\\x2e\\x2e\\x2f") == "../"

    def test_html_named_entity(self) -> None:
        assert decode_evasion("&amp;") == "&"

    def test_html_numeric_entity(self) -> None:
        assert decode_evasion("&#60;") == "<"


class TestDecodeMultiLayer:
    """Multi-layer (nested) encoding tests."""

    def test_double_url(self) -> None:
        """Double URL encoding: %252e → %2e → ."""
        assert decode_evasion("%252e%252e%252f") == "../"

    def test_url_plus_html_nesting(self) -> None:
        """URL-encoded HTML entity: %26lt%3B → &lt; → <"""
        assert decode_evasion("%26lt%3B") == "<"

    def test_triple_encoding(self) -> None:
        """Triple URL encoding: %25252e → %252e → %2e → . (3 layers)."""
        result = decode_evasion("%25252e%25252e%25252f")
        assert result == "../"

    def test_triple_encoding_needs_three_layers(self) -> None:
        """With max_layers=2, triple encoding leaves one layer."""
        result = decode_evasion("%25252e%25252e%25252f", max_layers=2)
        assert result == "%2e%2e%2f"

    def test_quadruple_encoding_default_limit(self) -> None:
        """Quadruple encoding only decodes 3 layers by default."""
        # %2525252e → %25252e → %252e → %2e (3 layers, one layer remains)
        result = decode_evasion("%2525252e%2525252e%2525252f")
        assert result == "%2e%2e%2f"

    def test_quadruple_encoding_with_higher_limit(self) -> None:
        """Quadruple encoding fully decoded with max_layers=4."""
        result = decode_evasion("%2525252e%2525252e%2525252f", max_layers=4)
        assert result == "../"


class TestDecodeMaxLayers:
    """max_layers parameter tests."""

    def test_max_layers_one(self) -> None:
        """Only one layer peeled."""
        result = decode_evasion("%252e%252e%252f", max_layers=1)
        assert result == "%2e%2e%2f"

    def test_max_layers_zero(self) -> None:
        """No-op — text returned unchanged."""
        assert decode_evasion("%2e%2e%2f", max_layers=0) == "%2e%2e%2f"

    def test_max_layers_negative(self) -> None:
        """Negative max_layers treated as zero — no-op."""
        assert decode_evasion("%2e%2e%2f", max_layers=-1) == "%2e%2e%2f"


class TestDecodeCleanText:
    """Clean text passes through unchanged."""

    def test_plain_text_unchanged(self) -> None:
        assert decode_evasion("hello world") == "hello world"

    def test_empty_string(self) -> None:
        assert decode_evasion("") == ""

    def test_unicode_text_unchanged(self) -> None:
        assert decode_evasion("漢字ひらがな") == "漢字ひらがな"


class TestDecodeInvalidEncoding:
    """Invalid/partial encodings don't error."""

    def test_invalid_url_encoding(self) -> None:
        assert decode_evasion("%ZZ") == "%ZZ"

    def test_partial_hex_escape(self) -> None:
        assert decode_evasion("\\xGG") == "\\xGG"

    def test_incomplete_url_encoding(self) -> None:
        assert decode_evasion("%2") == "%2"

    def test_incomplete_hex_escape(self) -> None:
        assert decode_evasion("\\x2") == "\\x2"

    def test_malformed_utf8_percent_preserved(self) -> None:
        """%FF is not valid UTF-8 — must pass through unchanged."""
        assert decode_evasion("%FF") == "%FF"

    def test_lone_continuation_byte_preserved(self) -> None:
        """%80 is a continuation byte without a start — must be preserved."""
        assert decode_evasion("%80") == "%80"

    def test_truncated_multibyte_preserved(self) -> None:
        """%C3 without a following byte — must be preserved."""
        assert decode_evasion("%C3") == "%C3"

    def test_valid_multibyte_still_decodes(self) -> None:
        """%C3%A9 is valid UTF-8 for é — must decode normally."""
        assert decode_evasion("%C3%A9") == "é"

    def test_mixed_valid_and_malformed(self) -> None:
        """Valid sequences decode, malformed ones stay as percent-encoded."""
        assert decode_evasion("%C3%A9%FF") == "é%FF"


class TestDecodeLogging:
    """Warning logging tests."""

    def test_logs_layer_count(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            decode_evasion("%252e%252e%252f")
        assert "Decoded 2 encoding layer(s) from value" in caplog.text

    def test_single_layer_log(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            decode_evasion("%2e%2e%2f")
        assert "Decoded 1 encoding layer(s) from value" in caplog.text

    def test_no_log_for_clean_text(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            decode_evasion("hello world")
        assert "Decoded" not in caplog.text

    def test_no_decoded_content_in_log(self, caplog: pytest.LogCaptureFixture) -> None:
        """Decoded content must never appear in log messages."""
        with caplog.at_level(logging.WARNING, logger="navi_sanitize"):
            decode_evasion("%3Cscript%3Ealert%28%29%3C%2Fscript%3E")
        for record in caplog.records:
            assert "<script>" not in record.message
            assert "alert" not in record.message


class TestDecodeIntegration:
    """Integration with clean() and escapers."""

    def test_decode_then_clean_path(self) -> None:
        """Decoded path traversal is stripped by path_escaper."""
        result = clean(
            decode_evasion("%252e%252e/etc/passwd"),
            escaper=path_escaper,
        )
        assert ".." not in result
        assert not result.startswith("/")
        assert "\\" not in result
        assert "etc" in result
        assert "passwd" in result

    def test_decode_then_clean_no_escaper(self) -> None:
        """Decoded text goes through clean() universal stages."""
        result = clean(decode_evasion("%00hello"))
        assert "\x00" not in result
        assert "hello" in result

    def test_full_pipeline(self) -> None:
        """decode_evasion → clean → detect_scripts composition."""
        from navi_sanitize import detect_scripts

        raw = "%70%61ypal.com"  # URL-encoded "paypal.com"
        decoded = decode_evasion(raw)
        cleaned = clean(decoded)
        scripts = detect_scripts(cleaned)
        assert scripts == {"latin"}
