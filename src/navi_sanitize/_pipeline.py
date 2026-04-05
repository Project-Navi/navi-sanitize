# SPDX-License-Identifier: MIT
"""Core sanitization pipeline.

Six stages in strict order. Reordering breaks security:
1. Null bytes   — prevent C-level string truncation
2. Invisibles   — strip 492 chars (zero-width, format/control, VS, tag block, bidi, C0/C1)
3. NFKC         — normalize fullwidth and compatibility forms
4. Homoglyphs   — replace confusable characters with Latin equivalents
5. Re-NFKC      — re-normalize if homoglyphs were replaced (idempotency)
6. Escaper      — caller-supplied context-specific escaping (optional)
"""

from __future__ import annotations

import logging
import unicodedata
from collections.abc import Callable
from typing import cast

from navi_sanitize._homoglyphs import HOMOGLYPH_MAP
from navi_sanitize._invisible import INVISIBLE_RE

logger = logging.getLogger("navi_sanitize")

Escaper = Callable[[str], str]  # Trust boundary: output is not re-sanitized


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


def _normalize_nfkc(s: str) -> tuple[str, int]:
    """NFKC normalize. Returns (cleaned, count of changed codepoints)."""
    normalized = unicodedata.normalize("NFKC", s)
    if normalized == s:
        return s, 0
    count = sum(1 for c in s if unicodedata.normalize("NFKC", c) != c)
    return normalized, max(count, 1)  # at least 1 if string changed


def _replace_homoglyphs(s: str) -> tuple[str, int]:
    """Replace homoglyphs with Latin equivalents. Returns (cleaned, count).

    Decomposes to NFD first so that combining marks cannot hide
    mapped base characters (e.g., Cyrillic U+0430 + breve composes
    to U+04D1 in NFKC, but NFD exposes the base char for replacement).
    """
    decomposed = unicodedata.normalize("NFD", s)
    count = 0
    chars = list(decomposed)
    for i, ch in enumerate(chars):
        if ch in HOMOGLYPH_MAP:
            chars[i] = HOMOGLYPH_MAP[ch]
            count += 1
    result = "".join(chars)
    # Recompose so the caller always gets NFC-stable text, even when
    # no replacements were made (NFD would otherwise leak out).
    result = unicodedata.normalize("NFC", result)
    return result, count


def clean(text: str, *, escaper: Escaper | None = None) -> str:
    """Sanitize a single string through the universal pipeline.

    Stages (in order):
    1. Null byte removal
    2. Invisible character stripping (492 chars across 9 categories)
    3. NFKC normalization (fullwidth → standard forms)
    4. Homoglyph replacement (Cyrillic/Greek/Armenian/Cherokee/typographic → Latin)
    5. Re-NFKC (if homoglyphs were replaced — ensures idempotency)
    6. Escaper (if provided)

    Always returns output. Logs warnings when input is modified.

    Security note: The escaper runs as the final stage. Its output is NOT
    re-sanitized through the pipeline. Built-in escapers (jinja2_escaper,
    path_escaper) are tested and safe. Custom escapers are within the
    caller's trust boundary — if a custom escaper introduces hostile
    characters, those characters will appear in the output.
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
    text, nfkc_count = _normalize_nfkc(text)
    if nfkc_count:
        logger.warning("Normalized %d fullwidth/compatibility character(s) in value", nfkc_count)

    # Stage 4: Homoglyphs
    text, glyph_count = _replace_homoglyphs(text)
    if glyph_count:
        logger.warning("Replaced %d homoglyph(s) in value", glyph_count)
        # Stage 5: Re-NFKC — homoglyph replacement can produce Latin chars that
        # combine with adjacent combining marks (e.g. Greek U+03A5 + combining
        # tilde -> Latin Y + combining tilde -> NFKC composes to U+1EF8).
        text, _ = _normalize_nfkc(text)

    # Stage 6: Escaper
    if escaper is not None:
        text = escaper(text)
        if not isinstance(text, str):
            raise TypeError(f"Escaper must return str, got {type(text).__name__}")

    return text


def walk[T](data: T, *, escaper: Escaper | None = None, max_depth: int = 128) -> T:
    """Recursively sanitize every string in a dict/list/nested structure.

    Non-string values pass through unchanged. Always returns output.
    Like clean(), walk() never crashes on data shape — only programming
    errors (max_depth < 0) raise ValueError.

    Uses a single iterative pass (no recursion, no deepcopy) so hostile
    nesting depth cannot cause stack overflow. Logs a warning when nesting
    exceeds *max_depth* but continues sanitizing. Cyclic references are
    handled via identity tracking — each container is copied and sanitized
    exactly once.

    Only dict and list contents are traversed; tuples, sets, and other
    types pass through by reference.
    """
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")

    # Scalars and strings — no traversal needed
    if isinstance(data, str):
        # clean() returns str; T is str (or a subclass whose extra semantics
        # sanitization intentionally discards).  Mypy can't prove str <: T.
        return cast(T, clean(data, escaper=escaper))
    if not isinstance(data, (dict, list)):
        return data

    # Single-pass iterative copy-and-sanitize (boltons remap pattern).
    # Each stack entry pairs (original, its_new_copy, depth). Children
    # are pushed onto the stack instead of recursing. The `seen` dict
    # maps id(original) -> copy to handle cycles and shared substructures.
    #
    # We maintain two parallel stacks — one for dicts, one for lists —
    # so mypy can narrow types without casts or ignores.
    seen: dict[int, dict[object, object] | list[object]] = {}
    depth_warned = False
    dict_stack: list[tuple[dict[object, object], dict[object, object], int]] = []
    list_stack: list[tuple[list[object], list[object], int]] = []

    if isinstance(data, dict):
        root_d: dict[object, object] = {}
        seen[id(data)] = root_d
        dict_stack.append((data, root_d, 0))
        result: object = root_d
    else:
        root_l: list[object] = []
        seen[id(data)] = root_l
        list_stack.append((data, root_l, 0))
        result = root_l

    def _resolve(v: object, depth: int) -> object:
        """Resolve a value: sanitize strings, schedule containers."""
        nonlocal depth_warned
        if isinstance(v, str):
            return clean(v, escaper=escaper)
        if isinstance(v, dict):
            obj_id = id(v)
            if obj_id in seen:
                return seen[obj_id]
            child_d: dict[object, object] = {}
            seen[obj_id] = child_d
            dict_stack.append((v, child_d, depth + 1))
            return child_d
        if isinstance(v, list):
            obj_id = id(v)
            if obj_id in seen:
                return seen[obj_id]
            child_l: list[object] = []
            seen[obj_id] = child_l
            list_stack.append((v, child_l, depth + 1))
            return child_l
        return v  # int, float, bool, None, tuple, set, bytes

    while dict_stack or list_stack:
        if dict_stack:
            orig_d, copy_d, depth = dict_stack.pop()
            if depth >= max_depth and not depth_warned:
                logger.warning(
                    "walk() input exceeds max_depth=%d; continuing to sanitize",
                    max_depth,
                )
                depth_warned = True
            for k, v in orig_d.items():
                new_k = clean(k, escaper=escaper) if isinstance(k, str) else k
                copy_d[new_k] = _resolve(v, depth)
        elif list_stack:
            orig_l, copy_l, depth = list_stack.pop()
            if depth >= max_depth and not depth_warned:
                logger.warning(
                    "walk() input exceeds max_depth=%d; continuing to sanitize",
                    max_depth,
                )
                depth_warned = True
            for item in orig_l:
                copy_l.append(_resolve(item, depth))

    # result is the root copy (dict or list) — structurally T but typed as
    # object because the stack-based builder can't carry T through.
    return cast(T, result)
