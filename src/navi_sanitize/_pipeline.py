# SPDX-License-Identifier: MIT
"""Core sanitization pipeline.

Five stages + optional escaper. Order matters:
1. Null bytes   — prevent C-level string truncation
2. Invisibles   — strip zero-width, tag block, bidi controls
3. NFKC         — normalize fullwidth and compatibility forms
4. Homoglyphs   — replace confusable characters with ASCII
5. Re-NFKC      — re-normalize if homoglyphs were replaced (idempotency)
6. Escaper      — caller-supplied context-specific escaping
"""

from __future__ import annotations

import logging
import unicodedata
from collections.abc import Callable
from copy import deepcopy

from navi_sanitize._homoglyphs import HOMOGLYPH_MAP
from navi_sanitize._invisible import INVISIBLE_RE

logger = logging.getLogger("navi_sanitize")

Escaper = Callable[[str], str]


def _strip_null_bytes(s: str) -> tuple[str, int]:
    """Strip null bytes. Returns (cleaned, count_removed)."""
    count = s.count("\x00")
    if count:
        return s.replace("\x00", ""), count
    return s, 0


def _strip_invisible(s: str) -> tuple[str, int]:
    """Strip invisible characters. Returns (cleaned, count_removed)."""
    count = len(INVISIBLE_RE.findall(s))
    if count:
        return INVISIBLE_RE.sub("", s), count
    return s, 0


def _normalize_nfkc(s: str) -> tuple[str, bool]:
    """NFKC normalize. Returns (cleaned, changed)."""
    normalized = unicodedata.normalize("NFKC", s)
    return normalized, normalized != s


def _replace_homoglyphs(s: str) -> tuple[str, int]:
    """Replace homoglyphs with ASCII equivalents. Returns (cleaned, count)."""
    count = 0
    chars = list(s)
    for i, ch in enumerate(chars):
        if ch in HOMOGLYPH_MAP:
            chars[i] = HOMOGLYPH_MAP[ch]
            count += 1
    return "".join(chars), count


def clean(text: str, *, escaper: Escaper | None = None) -> str:
    """Sanitize a single string through the universal pipeline.

    Stages (in order):
    1. Null byte removal
    2. Invisible character stripping (zero-width, tag block, bidi)
    3. NFKC normalization (fullwidth → ASCII)
    4. Homoglyph replacement (Cyrillic/Greek → Latin)
    5. Re-NFKC (if homoglyphs were replaced — ensures idempotency)
    6. Escaper (if provided)

    Always returns output. Logs warnings when input is modified.
    """
    if not isinstance(text, str):
        raise TypeError(f"clean() requires str, got {type(text).__name__}")

    # Stage 1: Null bytes
    text, null_count = _strip_null_bytes(text)
    if null_count:
        logger.warning("Removed %d null byte(s) from value", null_count)

    # Stage 2: Invisible characters
    text, invis_count = _strip_invisible(text)
    if invis_count:
        logger.warning("Stripped %d invisible character(s) from value", invis_count)

    # Stage 3: NFKC normalization
    text, had_nfkc = _normalize_nfkc(text)
    if had_nfkc:
        logger.warning("Normalized fullwidth character(s) in value")

    # Stage 4: Homoglyphs
    text, glyph_count = _replace_homoglyphs(text)
    if glyph_count:
        logger.warning("Replaced %d homoglyph(s) in value", glyph_count)
        # Re-normalize: homoglyph replacement can produce Latin chars that
        # combine with adjacent combining marks (e.g. Greek U+03A5 + combining
        # tilde -> Latin Y + combining tilde -> NFKC composes to U+1EF8).
        text, _ = _normalize_nfkc(text)

    # Stage 5: Escaper
    if escaper is not None:
        text = escaper(text)
        if not isinstance(text, str):
            raise TypeError(f"Escaper must return str, got {type(text).__name__}")

    return text


def walk[T](data: T, *, escaper: Escaper | None = None) -> T:
    """Recursively sanitize every string in a dict/list/nested structure.

    Non-string values pass through unchanged. Returns a deep copy.
    """
    copied = deepcopy(data)
    return _walk_inner(copied, escaper=escaper)  # type: ignore[return-value]


def _walk_inner(obj: object, *, escaper: Escaper | None = None) -> object:
    """Walk and sanitize in place on the deep-copied structure."""
    if isinstance(obj, dict):
        new_dict: dict[object, object] = {}
        for k, v in obj.items():
            clean_key = clean(k, escaper=escaper) if isinstance(k, str) else k
            new_dict[clean_key] = _walk_inner(v, escaper=escaper)
        obj.clear()
        obj.update(new_dict)
        return obj
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            obj[i] = _walk_inner(item, escaper=escaper)
        return obj
    if isinstance(obj, str):
        return clean(obj, escaper=escaper)
    return obj
