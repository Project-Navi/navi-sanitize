# SPDX-License-Identifier: MIT
"""Jinja2 delimiter escaper."""

from __future__ import annotations

import re

# Each match is a maximal chain of overlapping delimiters ("{{%", "{%}", "%}}"),
# so no raw delimiter can form between an escaped character and the next one.
# Factored after the leading "{" so plain "{{" runs do not backtrack.
_JINJA2_ESCAPE_RE = re.compile(r"\{(?:\{+(?:[%#]\}*)?|[%#]\}*)|[%#]\}+|\}{2,}")


def _escape_match(m: re.Match[str]) -> str:
    """Backslash-escape every character in the matched delimiter."""
    return "".join("\\" + c for c in m.group())


def jinja2_escaper(text: str) -> str:
    """Escape Jinja2's default template delimiters in a string.

    Backslash-escapes each character of {{ }} {% %} {# #}, including brace
    runs ({{{, }}}) and overlapping sequences ({{%, %}}), in a single pass.
    Breaks up the default delimiters only; it does not escape HTML, validate
    templates, or handle custom delimiter settings.
    """
    return _JINJA2_ESCAPE_RE.sub(_escape_match, text)
