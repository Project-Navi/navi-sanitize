# SPDX-License-Identifier: MIT
"""Path traversal escaper."""

from __future__ import annotations


def path_escaper(text: str) -> str:
    """Remove path traversal sequences from a string.

    Normalizes backslashes to forward slashes, then strips ../ and ./ segments,
    leading /, and embedded .. within segments (which can appear when earlier
    pipeline stages concatenate fragments).

    Lexical string cleanup only: no filesystem access, allowed-root check,
    symlink resolution, or drive-letter handling. The result may be empty.
    """
    text = text.replace("\\", "/")
    text = text.lstrip("/")
    parts = text.split("/")
    clean_parts: list[str] = []
    for part in parts:
        # Strip embedded ".." (e.g. null byte removal can fuse "safe.txt" + "../../").
        # Check the result, not the input: "..." becomes ".", a new dot segment.
        stripped = part.replace("..", "")
        if stripped and stripped != ".":
            clean_parts.append(stripped)
    return "/".join(clean_parts)
