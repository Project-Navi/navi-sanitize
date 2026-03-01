# SPDX-License-Identifier: MIT
"""Invisible character sets for stripping from untrusted text.

Data module — contains no logic, only character definitions.
Categories: zero-width, format/control, Unicode Tag block, bidirectional controls.
"""

from __future__ import annotations

import re

# --- Zero-width characters ---
ZERO_WIDTH_CHARS: set[str] = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
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

# --- Variation selectors (U+FE00-U+FE0F) ---
# Invisible modifiers that change glyph presentation.
VARIATION_SELECTOR_RANGE = (0xFE00, 0xFE0F)

# --- Unicode Tag block (U+E0001-U+E007F) ---
# Encodes invisible ASCII that tokenizers read but humans can't see.
# Used in tag smuggling attacks against LLMs.
TAG_BLOCK_RANGE = (0xE0001, 0xE007F)

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
    # Bidi controls (individual chars)
    + "|["
    + "".join(BIDI_CONTROL_CHARS)
    + "]"
)

INVISIBLE_RE: re.Pattern[str] = re.compile(_INVISIBLE_CHARS)
