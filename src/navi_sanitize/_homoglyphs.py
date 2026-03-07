# ruff: noqa: RUF003
# SPDX-License-Identifier: MIT
"""Homoglyph mapping data for confusable character replacement.

Data module — contains no logic, only the character map.
Cyrillic, Greek, Armenian, Cherokee, and typographic lookalikes.
"""

from __future__ import annotations

HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic → Latin (lowercase)
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0456": "i",  # Byelorussian-Ukrainian і
    "\u0455": "s",  # dze ѕ
    "\u0458": "j",  # je ј
    "\u04bb": "h",  # shha һ
    # Cyrillic → Latin (uppercase)
    "\u0410": "A",
    "\u0412": "B",
    "\u0415": "E",
    "\u041a": "K",
    "\u041c": "M",
    "\u041d": "H",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0422": "T",
    "\u0425": "X",
    "\u0406": "I",  # Byelorussian-Ukrainian І
    "\u0405": "S",  # dze Ѕ
    "\u0408": "J",  # je Ј
    # Armenian → Latin
    "\u0555": "O",  # oh Օ
    "\u054d": "S",  # seh Ս
    # Cherokee → Latin
    "\u13aa": "A",  # go Ꭺ
    # Greek → Latin (uppercase)
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0396": "Z",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
    # Greek → Latin (lowercase)
    "\u03b1": "a",
    "\u03b9": "i",  # iota ι
    "\u03bd": "v",  # nu ν
    "\u03bf": "o",
    "\u03c1": "p",  # rho ρ
    "\u03bc": "u",  # mu μ
    "\u03c5": "u",  # upsilon υ
    "\u03ba": "k",  # kappa κ
    "\u03c4": "t",  # tau τ
    "\u03b3": "y",  # gamma γ
    "\u03c9": "w",  # omega ω
    # Cyrillic Extended → Latin
    "\u04c0": "I",  # palochka Ӏ
    "\u04cf": "l",  # palochka (small) ӏ
    "\u0501": "d",  # komi de ԁ
    "\u051b": "q",  # qa ԛ
    "\u051d": "w",  # we ԝ
    # Latin Extended → Latin
    "\u0131": "i",  # dotless i ı
    # Typographic
    "\u2212": "-",  # minus sign
    "\u2013": "-",  # en dash
    "\u2014": "-",  # em dash
    "\u2018": "'",  # left single quote
    "\u2019": "'",  # right single quote
    "\u201c": '"',  # left double quote
    "\u201d": '"',  # right double quote
}
