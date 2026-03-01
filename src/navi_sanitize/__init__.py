# SPDX-License-Identifier: MIT
"""navi-sanitize: Input sanitization pipeline for untrusted text."""

from __future__ import annotations

import logging
from collections.abc import Callable

from navi_sanitize._pipeline import clean, walk
from navi_sanitize.escapers import jinja2_escaper, path_escaper

Escaper = Callable[[str], str]

__version__ = "0.1.0"
__all__ = ["Escaper", "clean", "jinja2_escaper", "path_escaper", "walk"]

# Library logging best practice: NullHandler
logging.getLogger("navi_sanitize").addHandler(logging.NullHandler())
