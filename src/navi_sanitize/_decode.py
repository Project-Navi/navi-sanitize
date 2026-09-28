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

logger = logging.getLogger("navi_sanitize")

MAX_DECODE_LAYERS: int = 3

_HEX_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_PERCENT_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")


def _decode_percent_run(m: re.Match[str]) -> str:
    """Decode one run of consecutive ``%XX`` escapes."""
    raw = bytes.fromhex(m.group().replace("%", ""))
    # Decode valid UTF-8; map invalid bytes to surrogates so we can
    # re-encode them back to %XX in the next step.
    text = raw.decode("utf-8", errors="surrogateescape")
    return "".join(f"%{ord(ch) & 0xFF:02X}" if "\udc80" <= ch <= "\udcff" else ch for ch in text)


def _decode_url(s: str) -> str:
    """Decode URL percent-encoding, preserving malformed byte sequences.

    Valid UTF-8 percent-encoded sequences decode normally.
    Invalid byte sequences (e.g. ``%FF``, lone ``%80``) are kept
    as literal percent-encoded text instead of being replaced with
    U+FFFD. Only ``%XX`` runs are converted, so literal text (including
    lone surrogates, which cannot be UTF-8 encoded) passes through as-is.
    A literal character always ends a run: its UTF-8 form never begins
    with a continuation byte, so it cannot complete an encoded sequence.
    """
    return _PERCENT_RUN_RE.sub(_decode_percent_run, s)


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
    unchanged. Raises ``TypeError`` if *text* is not a ``str``.
    """
    if not isinstance(text, str):
        raise TypeError(f"decode_evasion() requires str, got {type(text).__name__}")
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
