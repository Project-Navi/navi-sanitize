# ruff: noqa: RUF001, RUF003
"""Bypass attempts — try to get hostile input past the pipeline.

These tests are written from the attacker's perspective.
A PASSING test means the attack was BLOCKED.
A FAILING test means we found a real bypass.
"""

from __future__ import annotations

from navi_sanitize import clean, jinja2_escaper, path_escaper

# =============================================================================
# HOMOGLYPH MAP GAPS — confusables not in the 42-pair map
# =============================================================================


class TestHomoglyphMapGaps:
    """The map has 42 pairs. Unicode has thousands of confusables.
    Can we sneak lookalikes through?"""

    # --- Armenian lookalikes ---
    def test_armenian_oh(self) -> None:
        # Armenian Օ (U+0555) looks like Latin O
        result = clean("\u0555pen")
        assert result == "Open", f"Armenian Օ slipped through: {result!r}"

    def test_armenian_seh(self) -> None:
        # Armenian Ս (U+054D) looks like Latin S
        result = clean("\u054derver")
        assert result == "Server", f"Armenian Ս slipped through: {result!r}"

    # --- Cherokee lookalikes ---
    def test_cherokee_a(self) -> None:
        # Cherokee Ꭺ (U+13AA) looks like Latin A
        result = clean("\u13aadmin")
        assert result == "Admin", f"Cherokee Ꭺ slipped through: {result!r}"

    # --- Mathematical symbols ---
    def test_math_italic_a(self) -> None:
        # Mathematical italic small a (U+1D44E)
        result = clean("\U0001d44edmin")
        # NFKC should normalize this to Latin 'a'
        assert result == "admin", f"Math italic 𝑎 slipped through: {result!r}"

    def test_math_bold_a(self) -> None:
        # Mathematical bold A (U+1D400)
        result = clean("\U0001d400dmin")
        assert result == "Admin", f"Math bold 𝐀 slipped through: {result!r}"

    def test_math_script_l(self) -> None:
        # Mathematical script small l (U+1D4C1)
        result = clean("\U0001d4c1ogin")
        assert result == "login", f"Math script 𝓁 slipped through: {result!r}"

    def test_math_fraktur_s(self) -> None:
        # Mathematical fraktur S (U+1D516) — NFKC normalizes to S
        result = clean("\U0001d516oot")
        assert result == "Soot", f"Math fraktur 𝔖 slipped through: {result!r}"

    def test_fullwidth_already_handled(self) -> None:
        # Sanity check — fullwidth IS handled by NFKC
        assert clean("\uff41\uff42\uff43") == "abc"

    # --- Cyrillic beyond the map ---
    def test_cyrillic_i(self) -> None:
        # Cyrillic і (U+0456) — Ukrainian i, looks like Latin i
        result = clean("adm\u0456n")
        assert result == "admin", f"Cyrillic і slipped through: {result!r}"

    def test_cyrillic_s(self) -> None:
        # Cyrillic ѕ (U+0455) — looks like Latin s
        result = clean("pa\u0455\u0455word")
        assert result == "password", f"Cyrillic ѕ slipped through: {result!r}"

    def test_cyrillic_j(self) -> None:
        # Cyrillic ј (U+0458) — looks like Latin j
        result = clean("\u0458ava")
        assert result == "java", f"Cyrillic ј slipped through: {result!r}"

    # --- Latin Extended lookalikes ---
    def test_latin_long_s(self) -> None:
        # ſ (U+017F) — long s, NFKC normalizes to Latin s
        assert clean("\u017file") == "sile"


# =============================================================================
# INVISIBLE CHARACTERS NOT IN THE STRIP LIST
# =============================================================================


class TestInvisibleGaps:
    """Characters that are invisible/near-invisible but not stripped."""

    def test_soft_hyphen(self) -> None:
        # U+00AD — soft hyphen, invisible in most contexts
        result = clean("pass\u00adword")
        assert result == "password", f"Soft hyphen slipped through: {result!r}"

    def test_hair_space(self) -> None:
        # U+200A — hair space, nearly invisible thin space
        result = clean("admin\u200aistrator")
        assert result == "administrator", f"Hair space slipped through: {result!r}"

    def test_thin_space(self) -> None:
        # U+2009 — thin space
        result = clean("pass\u2009word")
        assert result == "password", f"Thin space slipped through: {result!r}"

    def test_zero_width_no_break(self) -> None:
        # U+FEFF is in our list (BOM). Sanity check.
        assert clean("te\ufeffst") == "test"

    def test_variation_selector(self) -> None:
        # U+FE00-U+FE0F — variation selectors, invisible modifiers
        result = clean("test\ufe00ing")
        assert result == "testing", f"Variation selector slipped through: {result!r}"

    def test_interlinear_annotation(self) -> None:
        # U+FFF9-U+FFFB — interlinear annotation markers (invisible anchors)
        # The markers are stripped; text between them is visible content
        result = clean("te\ufff9hidden\ufffbst")
        assert "\ufff9" not in result
        assert "\ufffb" not in result
        assert result == "tehiddenst"

    def test_object_replacement(self) -> None:
        # U+FFFC — object replacement character
        result = clean("hello\ufffcworld")
        assert result == "helloworld", f"Object replacement slipped through: {result!r}"

    def test_line_separator(self) -> None:
        # U+2028 — line separator (invisible in many contexts, XSS vector)
        result = clean("hello\u2028world")
        assert result == "helloworld", f"Line separator slipped through: {result!r}"

    def test_paragraph_separator(self) -> None:
        # U+2029 — paragraph separator
        result = clean("hello\u2029world")
        assert result == "helloworld", f"Paragraph separator slipped through: {result!r}"

    def test_combining_grapheme_joiner(self) -> None:
        # U+034F — combining grapheme joiner, invisible
        result = clean("te\u034fst")
        assert result == "test", f"CGJ slipped through: {result!r}"


# =============================================================================
# JINJA2 ESCAPER BYPASSES
# =============================================================================


class TestJinja2EscaperBypasses:
    """Try to get {{ or {% through the escaper."""

    def test_fullwidth_braces_normalize_then_escape(self) -> None:
        # ｛｛ → {{ via NFKC, then escaper should catch it
        result = clean("\uff5b\uff5b config \uff5d\uff5d", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_homoglyph_inside_payload(self) -> None:
        # Even if delimiters are escaped, can we smuggle a confusable payload?
        result = clean("{{ c\u043enfig }}", escaper=jinja2_escaper)
        assert "{{" not in result
        assert "\u043e" not in result

    def test_zero_width_between_braces(self) -> None:
        # {\u200b{ — zero-width stripped first, then {{ formed, then escaped
        result = clean("{\u200b{ config }\u200b}", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_bidi_between_braces(self) -> None:
        result = clean("{\u202e{ config }\u202e}", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_tag_block_between_braces(self) -> None:
        tag_space = chr(0xE0000 + ord(" "))
        result = clean("{" + tag_space + "{ config }" + tag_space + "}", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_null_between_braces(self) -> None:
        result = clean("{\x00{ config }\x00}", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_triple_braces(self) -> None:
        # Jinja2 {{{ x }}} — contains {{ inside
        result = clean("{{{ config }}}", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_nested_template_tags(self) -> None:
        result = clean("{% for x in {{ items }} %}", escaper=jinja2_escaper)
        assert "{%" not in result
        assert "{{" not in result

    def test_backslash_already_escaped_input(self) -> None:
        # What if input already has \{\{ — does double-escaping happen?
        # Should not double-escape since \{ is not {{
        assert clean(r"\{\{ config \}\}", escaper=jinja2_escaper) == r"\{\{ config \}\}"


# =============================================================================
# PATH ESCAPER BYPASSES
# =============================================================================


class TestPathEscaperBypasses:
    """Try to escape the directory."""

    def test_backslash_traversal(self) -> None:
        # Windows-style path traversal — backslashes normalized to /
        result = clean("..\\..\\etc\\passwd", escaper=path_escaper)
        assert ".." not in result
        assert result == "etc/passwd"

    def test_url_encoded_dotdot(self) -> None:
        # %2e%2e/ — URL encoding of ../
        # path_escaper doesn't URL-decode — this is application-layer responsibility
        # The literal %2e%2e is not ".." so it passes through
        assert ".." not in clean("%2e%2e/%2e%2e/etc/passwd", escaper=path_escaper)

    def test_double_slash(self) -> None:
        result = clean("//etc/passwd", escaper=path_escaper)
        assert not result.startswith("/")

    def test_dotdot_with_spaces(self) -> None:
        # ".. " is not ".." — the space makes it a different segment
        result = clean(".. /.. /etc/passwd", escaper=path_escaper)
        assert ".." not in result

    def test_null_in_path(self) -> None:
        # Null byte truncation attack on paths
        result = clean("safe.txt\x00../../etc/passwd", escaper=path_escaper)
        assert "\x00" not in result
        assert ".." not in result

    def test_fullwidth_slash(self) -> None:
        # Fullwidth / (U+FF0F) — does NFKC normalize it?
        result = clean("..\uff0f..\uff0fetc\uff0fpasswd", escaper=path_escaper)
        # NFKC normalizes ／ to / — then path_escaper should strip ../
        assert ".." not in result


# =============================================================================
# STAGE ORDER EXPLOITS
# =============================================================================


class TestStageOrderExploits:
    """The pipeline runs stages in fixed order. Can we exploit that?"""

    def test_nfkc_creates_homoglyph_after_homoglyph_stage(self) -> None:
        # NFKC runs BEFORE homoglyphs — verify NFKC output is caught.
        # Mathematical italic small a (U+1D44E) normalizes to 'a' via NFKC,
        # which is already Latin — not a homoglyph. Verify clean output.
        result = clean("\U0001d44edmin")
        assert result == "admin"

    def test_homoglyph_replacement_creates_jinja_delimiter(self) -> None:
        # Homoglyph map only maps to ASCII letters/digits/dashes/quotes,
        # never to { } % # — so replacement can't create new delimiters.
        # Verify by running all homoglyph map outputs through jinja2 escaper.
        from navi_sanitize._homoglyphs import HOMOGLYPH_MAP

        all_replacements = "".join(HOMOGLYPH_MAP.values())
        assert "{{" not in all_replacements
        assert "{%" not in all_replacements
        assert "{#" not in all_replacements

    def test_invisible_strip_creates_delimiter(self) -> None:
        # { + (invisible) + { → {{ after stripping
        # This is the core attack. Does the order handle it?
        result = clean("{\u200b{ config }\u200b}", escaper=jinja2_escaper)
        assert "{{" not in result  # Stage 2 strips, creating {{, Stage 5 escapes

    def test_nfkc_creates_delimiter(self) -> None:
        # Fullwidth { (U+FF5B) normalizes to { under NFKC
        # If we have ＋ ｛｛ — NFKC creates {{ — does escaper catch it?
        result = clean("\uff5b\uff5b evil \uff5d\uff5d", escaper=jinja2_escaper)
        assert "{{" not in result

    def test_invisible_strip_creates_dotdot_path(self) -> None:
        # . + (invisible) + . + / → ../ after stripping
        result = clean(".\u200b./.\u200b./etc/passwd", escaper=path_escaper)
        assert ".." not in result

    def test_nfkc_creates_dotdot(self) -> None:
        # Fullwidth . (U+FF0E) normalizes to . — can we create ../?
        result = clean("\uff0e\uff0e/\uff0e\uff0e/etc/passwd", escaper=path_escaper)
        assert ".." not in result

    def test_homoglyph_in_path_segment(self) -> None:
        # Cyrillic е in "etc" — homoglyph replaced, but path still works
        result = clean("../../\u0435tc/passwd", escaper=path_escaper)
        assert ".." not in result
        assert "etc" in result  # homoglyph was replaced


# =============================================================================
# ENCODING CHAIN ATTACKS
# =============================================================================


class TestEncodingChainAttacks:
    """Multi-step encoding that might survive individual stages."""

    def test_double_fullwidth(self) -> None:
        # What if fullwidth is applied twice? (Doesn't exist, but test stability)
        fw_a = "\uff41"  # fullwidth a
        result = clean(fw_a)
        second = clean(result)
        assert result == second == "a"

    def test_combining_plus_homoglyph(self) -> None:
        # Cyrillic а + combining acute accent
        result = clean("\u0430\u0301")
        # NFKC may compose Cyrillic а + acute into something
        # But homoglyph stage should still catch the Cyrillic а
        assert "\u0430" not in result

    def test_nfkc_decomposition_reveals_homoglyph(self) -> None:
        # Some NFKC decompositions produce characters in our homoglyph map
        # ﬁ (U+FB01) → "fi" — neither f nor i is a homoglyph, clean
        assert clean("\ufb01nd") == "find"

    def test_repeated_sanitization_is_idempotent(self) -> None:
        """clean(clean(x)) == clean(x) for all hostile inputs."""
        inputs = [
            "n\u0430vi\x00\u200b",
            "{{ c\u043enfig }}",
            "../../\u0435tc",
            "\uff54\uff45\uff53\uff54",
            "{\u200b{ x }\u200b}",
            "\x00" * 100,
            "".join(chr(0xE0000 + ord(c)) for c in "hidden"),
        ]
        for inp in inputs:
            first = clean(inp)
            second = clean(first)
            assert first == second, f"Not idempotent for {inp!r}: {first!r} != {second!r}"
