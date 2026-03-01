# SPDX-License-Identifier: MIT
"""Jinja2 delimiter escaper."""

from __future__ import annotations

import re

_JINJA2_DELIMITERS = re.compile(r"\{\{|\}\}|\{%|%\}|\{#|#\}")


def jinja2_escaper(text: str) -> str:
    """Escape Jinja2 template delimiters in a string.

    Replaces {{ }} {% %} {# #} with backslash-escaped equivalents.
    """
    if not _JINJA2_DELIMITERS.search(text):
        return text
    text = text.replace("{{", r"\{\{")
    text = text.replace("}}", r"\}\}")
    text = text.replace("{%", r"\{\%")
    text = text.replace("%}", r"\%\}")
    text = text.replace("{#", r"\{\#")
    text = text.replace("#}", r"\#\}")
    return text
