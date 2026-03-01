# SPDX-License-Identifier: MIT
"""Jinja2 delimiter escaper."""

from __future__ import annotations

import re

_JINJA2_ESCAPE_RE = re.compile(r"\{{2,}|\}{2,}|\{%|%\}|\{#|#\}")


def _escape_match(m: re.Match[str]) -> str:
    """Backslash-escape every character in the matched delimiter."""
    return "".join("\\" + c for c in m.group())


def jinja2_escaper(text: str) -> str:
    """Escape Jinja2 template delimiters in a string.

    Replaces {{ }} {% %} {# #} with backslash-escaped equivalents.
    Handles runs of 2+ braces (e.g. {{{ or }}}) in a single pass.
    """
    return _JINJA2_ESCAPE_RE.sub(_escape_match, text)
