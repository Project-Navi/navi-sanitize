# SPDX-License-Identifier: MIT
"""navi-sanitize: Input sanitization pipeline for untrusted text."""

from __future__ import annotations

import logging
from collections.abc import Callable

from navi_sanitize._decode import decode_evasion
from navi_sanitize._pipeline import clean, walk
from navi_sanitize._scripts import detect_scripts, is_mixed_script
from navi_sanitize.escapers import jinja2_escaper, path_escaper

Escaper = Callable[[str], str]

__version__ = "0.2.0"
__all__ = [
    "Escaper",
    "clean",
    "decode_evasion",
    "detect_scripts",
    "is_mixed_script",
    "jinja2_escaper",
    "path_escaper",
    "walk",
]

# Library logging best practice: NullHandler
logging.getLogger("navi_sanitize").addHandler(logging.NullHandler())
