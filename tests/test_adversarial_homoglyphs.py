# ruff: noqa: RUF001, RUF002
"""Adversarial tests for homoglyph bypasses found in stress testing.

NFKC composition bypass: combining marks hide homoglyph base chars.
"""

from __future__ import annotations

from navi_sanitize import clean


class TestNFKCCompositionBypass:
    """Combining marks must not hide homoglyph base characters."""

    def test_cyrillic_a_with_breve(self) -> None:
        """Cyrillic а + combining breve → should replace base а with Latin a."""
        result = clean("\u0430\u0306dmin")
        assert "\u0430" not in result, f"Cyrillic а survived: {result!r}"
        # NFKC of Latin a + breve = ă (U+0103)
        assert result[0] == "\u0103" or result[0] == "a"

    def test_cyrillic_a_with_diaeresis(self) -> None:
        result = clean("\u0430\u0308dmin")
        assert "\u0430" not in result, f"Cyrillic а survived: {result!r}"

    def test_cyrillic_e_with_grave(self) -> None:
        result = clean("\u0435\u0300mail")
        assert "\u0435" not in result, f"Cyrillic е survived: {result!r}"

    def test_cyrillic_e_with_diaeresis(self) -> None:
        result = clean("\u0435\u0308mail")
        assert "\u0435" not in result, f"Cyrillic е survived: {result!r}"

    def test_cyrillic_o_with_diaeresis(self) -> None:
        result = clean("p\u043e\u0308rt")
        assert "\u043e" not in result, f"Cyrillic о survived: {result!r}"

    def test_greek_alpha_with_grave(self) -> None:
        result = clean("\u03b1\u0300pple")
        assert "\u03b1" not in result, f"Greek α survived: {result!r}"

    def test_greek_iota_with_diaeresis(self) -> None:
        result = clean("\u03b9\u0308nput")
        assert "\u03b9" not in result, f"Greek ι survived: {result!r}"

    def test_greek_upsilon_with_tilde(self) -> None:
        """This was already tested — verifying it still works."""
        result = clean("\u03a5\u0303")
        assert "\u03a5" not in result

    def test_idempotent_after_nfd_fix(self) -> None:
        """clean(clean(x)) must still equal clean(x) after NFD change."""
        inputs = [
            "\u0430\u0306dmin",
            "\u0435\u0308mail",
            "\u03b1\u0300pple",
            "\u03a5\u0303",
            "\u0456\u0308test",  # Ukrainian ї base
        ]
        for text in inputs:
            first = clean(text)
            second = clean(first)
            assert first == second, f"Idempotency violated: {text!r} → {first!r} → {second!r}"
