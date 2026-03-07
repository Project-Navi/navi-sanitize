"""Adversarial tests for invisible character gaps found in stress testing."""

from __future__ import annotations

from navi_sanitize import clean


class TestC0ControlStripping:
    """C0 controls (U+0001-U+001F excl NUL/TAB/LF/CR) must be stripped."""

    def test_backspace_stripped(self) -> None:
        assert clean("hel\u0008lo") == "hello"

    def test_escape_stripped(self) -> None:
        assert clean("hello\u001b[31mRED") == "hello[31mRED"

    def test_vertical_tab_stripped(self) -> None:
        assert clean("hello\u000bworld") == "helloworld"

    def test_form_feed_stripped(self) -> None:
        assert clean("hello\u000cworld") == "helloworld"

    def test_bell_stripped(self) -> None:
        assert clean("hello\u0007world") == "helloworld"

    def test_preserves_tab(self) -> None:
        assert clean("hello\tworld") == "hello\tworld"

    def test_preserves_newline(self) -> None:
        assert clean("hello\nworld") == "hello\nworld"

    def test_preserves_carriage_return(self) -> None:
        assert clean("hello\rworld") == "hello\rworld"


class TestC1ControlStripping:
    """C1 controls (U+0080-U+009F) must be stripped."""

    def test_c1_csi_stripped(self) -> None:
        assert clean("hello\u009bworld") == "helloworld"

    def test_c1_nel_stripped(self) -> None:
        assert clean("hello\u0085world") == "helloworld"

    def test_c1_range_fully_stripped(self) -> None:
        c1 = "".join(chr(c) for c in range(0x80, 0xA0))
        assert clean(f"a{c1}b") == "ab"


class TestInvisibleMathOperators:
    """U+2061-U+2064 are literally named INVISIBLE in Unicode."""

    def test_function_application_stripped(self) -> None:
        assert clean("f\u2061(x)") == "f(x)"

    def test_invisible_times_stripped(self) -> None:
        assert clean("2\u2062x") == "2x"

    def test_invisible_separator_stripped(self) -> None:
        assert clean("x\u2063y") == "xy"

    def test_invisible_plus_stripped(self) -> None:
        assert clean("a\u2064b") == "ab"

    def test_invisible_math_evasion(self) -> None:
        """Full keyword hidden by invisible separators."""
        assert clean("s\u2063y\u2063s\u2063t\u2063e\u2063m") == "system"


class TestDeprecatedFormatChars:
    """U+206A-U+206F are deprecated Unicode format controls."""

    def test_inhibit_symmetric_swapping_stripped(self) -> None:
        assert clean("test\u206aing") == "testing"

    def test_all_deprecated_stripped(self) -> None:
        deprecated = "".join(chr(c) for c in range(0x206A, 0x2070))
        assert clean(f"a{deprecated}b") == "ab"


class TestBrailleBlank:
    """U+2800 (Braille Pattern Blank) renders as empty space."""

    def test_braille_blank_stripped(self) -> None:
        assert clean("hello\u2800world") == "helloworld"


class TestOghamSpace:
    """U+1680 (Ogham Space Mark) is an invisible space variant."""

    def test_ogham_space_stripped(self) -> None:
        assert clean("hello\u1680world") == "helloworld"


class TestHangulFillers:
    """Hangul fillers are invisible. U+3164/U+FFA0 NFKC to U+1160."""

    def test_hangul_jungseong_filler_stripped(self) -> None:
        assert clean("test\u1160ing") == "testing"

    def test_hangul_choseong_filler_stripped(self) -> None:
        assert clean("test\u115fing") == "testing"

    def test_nfkc_funneled_filler_stripped(self) -> None:
        """U+3164 NFKC-normalizes to U+1160, which must also be stripped."""
        assert clean("test\u3164ing") == "testing"


class TestMongolianFVS:
    """Mongolian Free Variation Selectors — functionally identical to VS1-16."""

    def test_mongolian_fvs1_stripped(self) -> None:
        assert clean("test\u180bing") == "testing"

    def test_mongolian_fvs3_stripped(self) -> None:
        assert clean("test\u180ding") == "testing"

    def test_mongolian_fvs4_stripped(self) -> None:
        assert clean("test\u180fing") == "testing"


class TestArabicLetterMark:
    """U+061C is a directional mark like already-stripped U+200E/U+200F."""

    def test_arabic_letter_mark_stripped(self) -> None:
        assert clean("test\u061cing") == "testing"
