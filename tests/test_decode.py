# SPDX-License-Identifier: MIT
"""Tests for multi-encoding evasion decode."""

from __future__ import annotations

import html
import logging
import re
import sys
import urllib.parse
from collections.abc import Iterator

import hypothesis.strategies as st
import pytest
from hypothesis import given, settings

from navi_sanitize import clean, decode_evasion, path_escaper

_HEX_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _legacy_decode_pass(s: str) -> str:
    """One pass of the pre-0.2.2 decoder, as an oracle for surrogate-free text."""
    text = urllib.parse.unquote_to_bytes(s).decode("utf-8", errors="surrogateescape")
    text = "".join(f"%{ord(ch) & 0xFF:02X}" if "\udc80" <= ch <= "\udcff" else ch for ch in text)
    text = html.unescape(text)
    return _HEX_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


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

    def test_encoded_surrogate_bytes_preserved(self) -> None:
        """UTF-8-encoded surrogates are invalid UTF-8 and stay percent text."""
        assert decode_evasion("%ED%A0%80") == "%ED%A0%80"


class TestDecodeLiteralSurrogates:
    """Literal lone surrogates are preserved, never encoded or replaced."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("\ud800", "\ud800"),
            ("\udbff\udc00x", "\udbff\udc00x"),
            ("pre\udfffpost", "pre\udfffpost"),
            ("\udc80", "\udc80"),  # the surrogateescape range is not special in input
            ("\udcff%41", "\udcffA"),
            ("%41\ud800&#66;", "A\ud800B"),
            ("%FF\udc80", "%FF\udc80"),
            ("%C3%A9\ud800%C3", "é\ud800%C3"),
            ("%C3\udc80%A9", "%C3\udc80%A9"),  # a literal splits an encoded sequence
            ("\ud800%252e%252e%252f", "\ud800../"),
        ],
    )
    def test_surrogates_preserved_while_decoding(self, text: str, expected: str) -> None:
        assert decode_evasion(text) == expected

    def test_surrogate_input_log_is_content_free(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.DEBUG, logger="navi_sanitize"):
            decode_evasion("SECRET\ud800%53ECRET")
        assert caplog.records
        for record in caplog.records:
            assert "SECRET" not in record.getMessage()
            assert "SECRET" not in repr(record.args)

    @given(text=st.text(st.characters(exclude_categories=()), max_size=60))
    @settings(max_examples=200)
    def test_never_raises_on_any_code_point(self, text: str) -> None:
        assert isinstance(decode_evasion(text), str)

    @given(
        text=st.lists(
            st.sampled_from(
                [
                    "%",
                    "C3",
                    "A9",
                    "E2",
                    "82",
                    "AC",
                    "FF",
                    "80",
                    "2",
                    "&#",
                    ";",
                    "é",
                    "0",
                    "65",
                    "&#x",
                ]
            )
            | st.characters(codec="utf-8"),
            max_size=40,
        ).map("".join)
    )
    @settings(max_examples=300)
    def test_matches_legacy_decoder_without_surrogates(self, text: str) -> None:
        """Only literal surrogates change behavior; everything else decodes as before."""
        assert decode_evasion(text, max_layers=1) == _legacy_decode_pass(text)

    def test_non_str_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="decode_evasion\\(\\) requires str"):
            decode_evasion(b"%41")  # type: ignore[arg-type]


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


@pytest.fixture(params=[4300, 640], ids=["limit4300", "limit640"])
def int_digit_limit(request: pytest.FixtureRequest) -> Iterator[int]:
    """Run at the default and minimum int-string limits; the library must not change them."""
    old = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(request.param)
    try:
        yield request.param
    finally:
        assert sys.get_int_max_str_digits() == request.param, "decoder changed the global limit"
        sys.set_int_max_str_digits(old)


@pytest.mark.usefixtures("int_digit_limit")
class TestLongDecimalReferences:
    """Decimal references longer than the interpreter's int-conversion limit must not raise."""

    def test_long_out_of_range_decimal(self) -> None:
        assert decode_evasion("&#" + "9" * 4301 + ";") == "\ufffd"

    def test_long_zero_padded_valid_decimal(self) -> None:
        assert decode_evasion("&#" + "0" * 4301 + "65;") == "A"

    def test_semicolonless_long_reference(self) -> None:
        assert decode_evasion("&#" + "0" * 4301 + "65") == "A"

    def test_mixed_references_and_surrogate(self) -> None:
        value = "\ud800%42&#" + "0" * 4301 + "65;&amp;%FF"
        assert decode_evasion(value, max_layers=1) == "\ud800BA&%FF"

    def test_url_exposes_long_reference_in_same_pass(self) -> None:
        assert decode_evasion("%26%23" + "0" * 4301 + "65%3B", max_layers=1) == "A"

    def test_html_exposes_reference_on_next_pass(self) -> None:
        entity = "&#" + "0" * 4301 + "65;"
        wrapped = "&amp;" + entity[1:]
        assert decode_evasion(wrapped, max_layers=1) == entity
        assert decode_evasion(wrapped, max_layers=2) == "A"

    def test_no_accidental_double_html_decoding(self) -> None:
        assert decode_evasion("&#38;#65;", max_layers=1) == "&#65;"
        assert decode_evasion("&#38;#65;", max_layers=2) == "A"
        assert decode_evasion("&#" + "0" * 4301 + "38;#65;", max_layers=1) == "&#65;"

    def test_nonpositive_layers_still_no_op(self) -> None:
        value = "&#" + "9" * 4301 + ";"
        for layers in (0, -1):
            assert decode_evasion(value, max_layers=layers) == value

    def test_html5_invalid_reference_semantics_preserved(self) -> None:
        assert decode_evasion("&#0;&#xD800;&#1114112;", max_layers=1) == "\ufffd" * 3
        assert decode_evasion("&#128;", max_layers=1) == "\u20ac"
        assert decode_evasion("&#" + "0" * 4301 + "128;", max_layers=1) == "\u20ac"
        assert decode_evasion("a&#1;b", max_layers=1) == "ab"  # HTML5 drops some code points

    def test_long_hex_still_handled(self) -> None:
        assert decode_evasion("&#x" + "F" * 5000 + ";", max_layers=1) == "\ufffd"

    def test_surrogate_and_malformed_percent_policy_preserved(self) -> None:
        assert decode_evasion("\ud800%41%FF") == "\ud800A%FF"

    def test_logging_does_not_leak_reference_content(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        secret = "NS_PRIVATE_SENTINEL"
        with caplog.at_level(logging.DEBUG, logger="navi_sanitize"):
            assert decode_evasion(secret + "&#" + "0" * 4301 + "65;") == secret + "A"
        assert caplog.records
        for record in caplog.records:
            assert secret not in record.getMessage() + repr(record.args)


class TestDecimalReferenceEquivalence:
    """Where html.unescape itself can convert, padded references decode exactly as it does."""

    @pytest.mark.parametrize(
        "value", ["0", "9", "65", "128", "1114111", "1114112", "9999999", "99999999", "38"]
    )
    @pytest.mark.parametrize("zeros", [0, 1, 7, 12])
    @pytest.mark.parametrize("tail", [";", "", "x;", ";;", "&#65;"])
    def test_matches_html_unescape(self, value: str, zeros: int, tail: str) -> None:
        text = "<&#" + "0" * zeros + value + tail + ">"
        assert decode_evasion(text, max_layers=1) == html.unescape(text)
