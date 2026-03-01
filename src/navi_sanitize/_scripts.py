# SPDX-License-Identifier: MIT
"""Mixed-script detection for untrusted text.

Opt-in analysis primitive — no transformation, no blocking. Callers use the
results to decide whether to warn, block, or confirm. Not part of the default
``clean()`` pipeline.

Only known script buckets are returned; characters whose Unicode name doesn't
match any known prefix are silently ignored.
"""

from __future__ import annotations

import unicodedata

# First token of unicodedata.name() → bucket
_SCRIPT_PREFIXES: dict[str, str] = {
    "LATIN": "latin",
    "CYRILLIC": "cyrillic",
    "GREEK": "greek",
    "ARABIC": "arabic",
    "HEBREW": "hebrew",
    "ARMENIAN": "armenian",
    "CHEROKEE": "cherokee",
    "CJK": "cjk",
    "HIRAGANA": "cjk",
    "KATAKANA": "cjk",
    "HANGUL": "cjk",
}


def detect_scripts(text: str) -> set[str]:
    """Return the set of script buckets present in *text*.

    Only alphabetic characters are considered; digits, punctuation, emoji,
    and characters with no Unicode name are skipped. Unknown scripts (not in
    the prefix map) are silently ignored.

    Buckets: ``latin``, ``cyrillic``, ``greek``, ``arabic``, ``hebrew``,
    ``armenian``, ``cherokee``, ``cjk`` (covers CJK Unified, Hiragana,
    Katakana, and Hangul).
    """
    scripts: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        if not name:
            continue
        head = name.split(" ", 1)[0]
        bucket = _SCRIPT_PREFIXES.get(head)
        if bucket is not None:
            scripts.add(bucket)
    return scripts


def is_mixed_script(text: str) -> bool:
    """Return ``True`` if *text* contains characters from two or more scripts.

    Non-alphabetic characters (digits, punctuation, emoji) are not counted,
    so ``"hello 123"`` is *not* considered mixed.
    """
    return len(detect_scripts(text)) >= 2
