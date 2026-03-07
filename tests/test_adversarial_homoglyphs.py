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


class TestGreekLowercaseGaps:
    """Greek lowercase homoglyphs added to the 66-pair map in 0.2.0."""

    def test_greek_mu(self) -> None:
        assert clean("\u03bcser") == "user"

    def test_greek_upsilon_lower(self) -> None:
        assert clean("\u03c5ser") == "user"

    def test_greek_kappa(self) -> None:
        assert clean("\u03baey") == "key"

    def test_greek_tau(self) -> None:
        assert clean("\u03c4est") == "test"

    def test_greek_gamma(self) -> None:
        assert clean("\u03b3es") == "yes"

    def test_greek_omega(self) -> None:
        assert clean("\u03c9eb") == "web"


class TestCyrillicExtendedGaps:
    """Cyrillic Extended homoglyphs added to the 66-pair map in 0.2.0."""

    def test_cyrillic_palochka_upper(self) -> None:
        """U+04C0 — indistinguishable from I/l."""
        assert clean("\u04c0nput") == "Input"

    def test_cyrillic_palochka_lower(self) -> None:
        """U+04CF — indistinguishable from l/I."""
        assert clean("\u04cfog") == "log"

    def test_cyrillic_komi_de(self) -> None:
        """U+0501 — looks like d."""
        assert clean("\u0501ata") == "data"

    def test_cyrillic_qa(self) -> None:
        """U+051B — looks like q."""
        assert clean("\u051buery") == "query"

    def test_cyrillic_we(self) -> None:
        """U+051D — looks like w."""
        assert clean("\u051deb") == "web"


class TestLatinDotlessI:
    """U+0131 (Latin dotless i) is near-identical to i in sans-serif."""

    def test_dotless_i(self) -> None:
        assert clean("adm\u0131n") == "admin"
