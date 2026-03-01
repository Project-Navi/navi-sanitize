# SPDX-License-Identifier: MIT
# ruff: noqa: RUF001, RUF003
"""Tests for mixed-script detection."""

from __future__ import annotations

from navi_sanitize import clean, detect_scripts, is_mixed_script


class TestDetectScripts:
    """Tests for detect_scripts()."""

    def test_pure_latin(self) -> None:
        assert detect_scripts("hello world") == {"latin"}

    def test_pure_cyrillic(self) -> None:
        assert detect_scripts("Привет") == {"cyrillic"}

    def test_pure_greek(self) -> None:
        assert detect_scripts("αβγδ") == {"greek"}

    def test_pure_arabic(self) -> None:
        assert detect_scripts("مرحبا") == {"arabic"}

    def test_pure_hebrew(self) -> None:
        assert detect_scripts("שלום") == {"hebrew"}

    def test_pure_armenian(self) -> None:
        assert detect_scripts("Հայաստան") == {"armenian"}

    def test_pure_cherokee(self) -> None:
        assert detect_scripts("ᏣᎳᎩ") == {"cherokee"}

    def test_cjk_chinese(self) -> None:
        assert detect_scripts("漢字") == {"cjk"}

    def test_cjk_japanese_hiragana(self) -> None:
        assert detect_scripts("ひらがな") == {"cjk"}

    def test_cjk_japanese_katakana(self) -> None:
        assert detect_scripts("カタカナ") == {"cjk"}

    def test_cjk_korean(self) -> None:
        assert detect_scripts("한글") == {"cjk"}

    def test_cjk_mixed_scripts_single_bucket(self) -> None:
        """Chinese + Japanese + Korean all map to 'cjk' — not mixed."""
        assert detect_scripts("漢字ひらがな한글") == {"cjk"}
        assert not is_mixed_script("漢字ひらがな한글")

    def test_mixed_latin_cyrillic(self) -> None:
        # "pаypal" — Cyrillic а (U+0430) mixed with Latin
        assert detect_scripts("pаypal") == {"latin", "cyrillic"}

    def test_mixed_latin_greek(self) -> None:
        # "AΒC" — Greek Β (U+0392) mixed with Latin A, C
        assert detect_scripts("AΒC") == {"latin", "greek"}

    def test_digits_only(self) -> None:
        assert detect_scripts("12345") == set()

    def test_punctuation_only(self) -> None:
        assert detect_scripts("!@#$%^&*()") == set()

    def test_emoji_only(self) -> None:
        assert detect_scripts("🎉🎊🎈") == set()

    def test_empty_string(self) -> None:
        assert detect_scripts("") == set()

    def test_latin_with_digits(self) -> None:
        """Digits are non-alphabetic — only Latin detected."""
        assert detect_scripts("hello123") == {"latin"}

    def test_latin_with_punctuation(self) -> None:
        assert detect_scripts("hello, world!") == {"latin"}


class TestDetectScriptsPhishing:
    """Phishing detection scenarios."""

    def test_paypal_cyrillic_a(self) -> None:
        # Cyrillic а (U+0430)
        assert detect_scripts("pаypal.com") == {"latin", "cyrillic"}

    def test_google_cyrillic_o(self) -> None:
        # Cyrillic о (U+043E)
        assert detect_scripts("gооgle.com") == {"latin", "cyrillic"}

    def test_apple_cyrillic_a(self) -> None:
        # Cyrillic а (U+0430)
        assert detect_scripts("аpple.com") == {"latin", "cyrillic"}

    def test_post_clean_paypal(self) -> None:
        """After clean(), homoglyphs are replaced — only Latin remains."""
        assert detect_scripts(clean("pаypal.com")) == {"latin"}

    def test_post_clean_google(self) -> None:
        assert detect_scripts(clean("gооgle.com")) == {"latin"}

    def test_post_clean_apple(self) -> None:
        assert detect_scripts(clean("аpple.com")) == {"latin"}


class TestIsMixedScript:
    """Tests for is_mixed_script()."""

    def test_mixed_true(self) -> None:
        assert is_mixed_script("pаypal.com") is True

    def test_pure_latin_false(self) -> None:
        assert is_mixed_script("hello world") is False

    def test_pure_cyrillic_false(self) -> None:
        assert is_mixed_script("Привет") is False

    def test_empty_false(self) -> None:
        assert is_mixed_script("") is False

    def test_digits_only_false(self) -> None:
        assert is_mixed_script("12345") is False

    def test_latin_with_digits_false(self) -> None:
        """'hello 123' is not mixed — digits are non-alphabetic."""
        assert is_mixed_script("hello 123") is False

    def test_multiple_scripts(self) -> None:
        # Latin + Cyrillic + Greek
        assert is_mixed_script("helloПриветαβγ") is True

    def test_cjk_with_latin(self) -> None:
        assert is_mixed_script("hello漢字") is True
