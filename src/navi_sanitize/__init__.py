# SPDX-License-Identifier: MIT
"""navi-sanitize: Input sanitization pipeline for untrusted text."""

from __future__ import annotations

import logging
from collections.abc import Callable
from importlib import metadata as importlib_metadata

from navi_sanitize._decode import decode_evasion
from navi_sanitize._pipeline import clean, walk
from navi_sanitize._scripts import detect_scripts, is_mixed_script
from navi_sanitize.escapers import jinja2_escaper, path_escaper

Escaper = Callable[[str], str]

try:
    __version__ = importlib_metadata.version("navi-sanitize")
except importlib_metadata.PackageNotFoundError:
    # Fallback for cases where package metadata is not available (e.g. source checkout)
    __version__ = "0.0.0"

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
