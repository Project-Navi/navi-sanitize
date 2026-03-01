# SPDX-License-Identifier: MIT
"""Multi-encoding evasion decoder for untrusted text.

Opt-in pre-processor — not part of the default ``clean()`` pipeline.
Callers compose it with ``clean()`` explicitly::

    text = decode_evasion(user_input)       # peel encoding layers
    cleaned = clean(text, escaper=...)      # sanitize

Iteratively decodes URL encoding, HTML entities, and hex escapes
(``\\xHH``). Stops when a full pass produces no changes or
*max_layers* is reached.
"""

from __future__ import annotations

import html
import logging
import re
import urllib.parse

logger = logging.getLogger("navi_sanitize")

MAX_DECODE_LAYERS: int = 3

_HEX_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _decode_url(s: str) -> str:
    """Decode URL percent-encoding."""
    return urllib.parse.unquote(s)


def _decode_html_entities(s: str) -> str:
    """Decode HTML/XML character entities."""
    return html.unescape(s)


def _decode_hex_escapes(s: str) -> str:
    r"""Decode literal ``\xHH`` escape sequences."""

    def _replace(m: re.Match[str]) -> str:
        return chr(int(m.group(1), 16))

    return _HEX_RE.sub(_replace, s)


def decode_evasion(text: str, *, max_layers: int = MAX_DECODE_LAYERS) -> str:
    """Iteratively decode nested encodings from *text*.

    Runs URL decoding, HTML entity unescaping, and hex escape decoding
    in sequence as a single pass. A pass counts as one layer if the
    output differs from the input. Stops when a pass produces no
    changes or *max_layers* is reached.

    Logs a warning with the layer count when decoding occurs. Never
    includes decoded content in log messages.

    Never errors on invalid or partial encodings — they pass through
    unchanged.
    """
    if max_layers <= 0:
        return text

    layers = 0
    for _ in range(max_layers):
        # Run all three decoders in sequence (one pass)
        decoded = _decode_url(text)
        decoded = _decode_html_entities(decoded)
        decoded = _decode_hex_escapes(decoded)
        # "changed" = output differs from input for this pass
        if decoded == text:
            break
        text = decoded
        layers += 1

    if layers:
        logger.warning("Decoded %d encoding layer(s) from value", layers)

    return text
