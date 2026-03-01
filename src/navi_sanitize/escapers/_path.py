# SPDX-License-Identifier: MIT
"""Path traversal escaper."""

from __future__ import annotations


def path_escaper(text: str) -> str:
    """Remove path traversal sequences from a string.

    Strips ../ and ./ segments, leading /, and embedded .. within segments
    (which can appear when earlier pipeline stages concatenate fragments).
    """
    text = text.replace("\\", "/")
    text = text.lstrip("/")
    parts = text.split("/")
    clean_parts: list[str] = []
    for part in parts:
        if part in ("..", "."):
            continue
        # Strip embedded ".." (e.g. null byte removal can fuse "safe.txt" + "../../")
        stripped = part.replace("..", "")
        if stripped:
            clean_parts.append(stripped)
    return "/".join(clean_parts)
