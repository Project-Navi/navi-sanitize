# SPDX-License-Identifier: MIT
"""Path traversal escaper."""

from __future__ import annotations


def path_escaper(text: str) -> str:
    """Remove path traversal sequences from a string.

    Strips ../ and ./ segments and leading /.
    """
    text = text.lstrip("/")
    parts = text.split("/")
    clean_parts: list[str] = []
    for part in parts:
        if part in ("..", "."):
            continue
        clean_parts.append(part)
    return "/".join(clean_parts)
