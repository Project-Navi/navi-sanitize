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
