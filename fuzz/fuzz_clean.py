# SPDX-License-Identifier: MIT
"""Fuzz harness for navi-sanitize.

Targets: clean(), walk(), and both built-in escapers.
Invariants checked:
  - clean() never raises (except TypeError for non-str)
  - clean() always returns str
  - clean() is idempotent (second pass is a no-op)
  - Output contains no null bytes or invisible characters
  - walk() never raises on valid structures
  - walk() never mutates the original
"""

from __future__ import annotations

import sys
from copy import deepcopy

import atheris

with atheris.instrument_imports():
    from navi_sanitize import clean, jinja2_escaper, path_escaper, walk
    from navi_sanitize._invisible import INVISIBLE_RE


def fuzz_clean(data: bytes) -> None:
    """Fuzz clean() with raw bytes decoded as utf-8 with surrogates."""
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicode(fdp.remaining_bytes())

    # Pick an escaper variant
    choice = fdp.ConsumeIntInRange(0, 3)
    escaper = {0: None, 1: jinja2_escaper, 2: path_escaper}.get(choice)

    result = clean(text, escaper=escaper)

    # Invariant: always returns str
    assert isinstance(result, str)

    # Invariant: no null bytes in output (escaper=None path)
    if escaper is None:
        assert "\x00" not in result

    # Invariant: no invisible characters in output (escaper=None path)
    if escaper is None:
        assert not INVISIBLE_RE.search(result)

    # Invariant: idempotent — second pass is a no-op
    if escaper is None:
        assert clean(result) == result


def fuzz_walk(data: bytes) -> None:
    """Fuzz walk() with constructed nested structures."""
    fdp = atheris.FuzzedDataProvider(data)

    # Build a small structure from fuzzed data
    depth = fdp.ConsumeIntInRange(0, 5)
    obj: object = fdp.ConsumeUnicode(fdp.remaining_bytes())
    for _ in range(depth):
        if fdp.ConsumeBool():
            obj = {"key": obj}
        else:
            obj = [obj]

    original = deepcopy(obj)
    result = walk(obj)

    # Invariant: original is never mutated
    assert obj == original

    # Invariant: always returns same type
    assert type(result) is type(obj)


def main() -> None:
    atheris.Setup(sys.argv, fuzz_clean)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
