# SPDX-License-Identifier: MIT
"""Invisible character sets for stripping from untrusted text.

Data module — contains no logic, only character definitions.
Categories: zero-width, format/control, variation selectors, variation selector
supplement, Unicode Tag block, bidirectional controls.
"""

from __future__ import annotations

import re

# --- Zero-width characters ---
ZERO_WIDTH_CHARS: set[str] = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u2060",  # word joiner
    "\ufeff",  # BOM / zero-width no-break space
    "\u180e",  # Mongolian vowel separator
}

# --- Format and control characters ---
# Invisible or near-invisible characters used in evasion attacks.
FORMAT_CHARS: set[str] = {
    "\u00ad",  # soft hyphen — invisible in most renderers
    "\u034f",  # combining grapheme joiner
    "\u2009",  # thin space
    "\u200a",  # hair space
    "\u2028",  # line separator (also XSS vector in JS)
    "\u2029",  # paragraph separator
    "\ufff9",  # interlinear annotation anchor
    "\ufffa",  # interlinear annotation separator
    "\ufffb",  # interlinear annotation terminator
    "\ufffc",  # object replacement character
}

# --- Variation selectors ---
# BMP range (U+FE00-U+FE0F) = VS1-VS16.
# Supplementary range (U+E0100-U+E01EF) = VS17-VS256.
# Both are invisible modifiers that change glyph presentation.
VARIATION_SELECTOR_RANGE = (0xFE00, 0xFE0F)
VARIATION_SELECTOR_SUPPLEMENT_RANGE = (0xE0100, 0xE01EF)

# --- Unicode Tag block (U+E0000-U+E007F) ---
# U+E0000 is the deprecated LANGUAGE TAG; U+E0001-U+E007F encode invisible
# ASCII that tokenizers read but humans can't see (tag smuggling attacks).
TAG_BLOCK_RANGE = (0xE0000, 0xE007F)

# --- C0 control characters (U+0001-U+001F) ---
# Excludes NUL (handled by stage 1), TAB (U+0009), LF (U+000A), CR (U+000D).
# Includes dangerous chars: BS (U+0008, terminal overwrite), ESC (U+001B, ANSI injection).
C0_CONTROL_RANGES = [(0x0001, 0x0008), (0x000B, 0x000C), (0x000E, 0x001F)]

# --- C1 control characters (U+0080-U+009F) ---
# Invisible in all modern contexts. U+009B (CSI) is equivalent to ESC+[.
C1_CONTROL_RANGE = (0x0080, 0x009F)

# --- Bidirectional override/isolate characters ---
# Used to reorder displayed text, hiding malicious content.
BIDI_CONTROL_CHARS: set[str] = {
    "\u202a",  # left-to-right embedding
    "\u202b",  # right-to-left embedding
    "\u202c",  # pop directional formatting
    "\u202d",  # left-to-right override
    "\u202e",  # right-to-left override
    "\u2066",  # left-to-right isolate
    "\u2067",  # right-to-left isolate
    "\u2068",  # first strong isolate
    "\u2069",  # pop directional isolate
}

# Single compiled regex for all invisible characters
_INVISIBLE_CHARS = (
    # Zero-width (individual chars)
    "["
    + "".join(ZERO_WIDTH_CHARS)
    + "]"
    # Format/control (individual chars)
    + "|["
    + "".join(FORMAT_CHARS)
    + "]"
    # Variation selectors (range)
    + "|["
    + chr(VARIATION_SELECTOR_RANGE[0])
    + "-"
    + chr(VARIATION_SELECTOR_RANGE[1])
    + "]"
    # Tag block (range)
    + "|["
    + chr(TAG_BLOCK_RANGE[0])
    + "-"
    + chr(TAG_BLOCK_RANGE[1])
    + "]"
    # Variation selectors supplement (range)
    + "|["
    + chr(VARIATION_SELECTOR_SUPPLEMENT_RANGE[0])
    + "-"
    + chr(VARIATION_SELECTOR_SUPPLEMENT_RANGE[1])
    + "]"
    # Bidi controls (individual chars)
    + "|["
    + "".join(BIDI_CONTROL_CHARS)
    + "]"
    # C0 controls (3 sub-ranges, excl NUL/TAB/LF/CR)
    + "|["
    + chr(C0_CONTROL_RANGES[0][0])
    + "-"
    + chr(C0_CONTROL_RANGES[0][1])
    + "]"
    + "|["
    + chr(C0_CONTROL_RANGES[1][0])
    + "-"
    + chr(C0_CONTROL_RANGES[1][1])
    + "]"
    + "|["
    + chr(C0_CONTROL_RANGES[2][0])
    + "-"
    + chr(C0_CONTROL_RANGES[2][1])
    + "]"
    # C1 controls (range)
    + "|["
    + chr(C1_CONTROL_RANGE[0])
    + "-"
    + chr(C1_CONTROL_RANGE[1])
    + "]"
)

INVISIBLE_RE: re.Pattern[str] = re.compile(_INVISIBLE_CHARS)
