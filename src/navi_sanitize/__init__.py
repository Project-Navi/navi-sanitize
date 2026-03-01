# SPDX-License-Identifier: MIT
"""navi-sanitize: Input sanitization pipeline for untrusted text."""

from __future__ import annotations

import logging
from collections.abc import Callable

from navi_sanitize._pipeline import clean, walk

Escaper = Callable[[str], str]

__version__ = "0.1.0"
__all__ = ["Escaper", "clean", "walk"]

# Library logging best practice: NullHandler
logging.getLogger("navi_sanitize").addHandler(logging.NullHandler())
