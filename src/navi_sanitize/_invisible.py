# SPDX-License-Identifier: MIT
"""Invisible character sets for stripping from untrusted text.

Data module — contains no logic, only character definitions.
Three categories: zero-width, Unicode Tag block, bidirectional controls.
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
