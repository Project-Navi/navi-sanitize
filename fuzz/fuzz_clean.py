# SPDX-License-Identifier: MIT
"""Fuzz harness for navi-sanitize.

Targets: clean() and walk() with built-in escapers.

Usage:
  python fuzz/fuzz_clean.py -atheris_runs=100000                      # fuzz_clean (default)
  python fuzz/fuzz_clean.py --target=fuzz_walk -atheris_runs=100000   # fuzz_walk
"""

from __future__ import annotations

import sys
import unicodedata
from copy import deepcopy

import atheris

with atheris.instrument_imports():
    from navi_sanitize import clean, jinja2_escaper, path_escaper, walk
    from navi_sanitize._homoglyphs import HOMOGLYPH_MAP
    from navi_sanitize._invisible import INVISIBLE_RE


def fuzz_clean(data: bytes) -> None:
    """Fuzz clean() with raw bytes decoded as unicode."""
    fdp = atheris.FuzzedDataProvider(data)

    # Pick an escaper variant before consuming text
    choice = fdp.ConsumeIntInRange(0, 3)
    escaper = {0: None, 1: jinja2_escaper, 2: path_escaper}.get(choice)

    text = fdp.ConsumeUnicode(fdp.remaining_bytes())
    result = clean(text, escaper=escaper)

    # Invariant: always returns str
    assert isinstance(result, str)

    if escaper is None:
        # Invariant: no null bytes
        assert "\x00" not in result

        # Invariant: no invisible characters
        assert not INVISIBLE_RE.search(result)

        # Invariant: no homoglyphs from the map
        assert not (set(result) & set(HOMOGLYPH_MAP))

        # Invariant: NFKC-stable
        assert unicodedata.normalize("NFKC", result) == result

        # Invariant: idempotent
        assert clean(result) == result


def fuzz_walk(data: bytes) -> None:
    """Fuzz walk() with constructed nested structures."""
    fdp = atheris.FuzzedDataProvider(data)

    # Build a small structure from fuzzed data
    depth = fdp.ConsumeIntInRange(0, 5)
    obj: object = fdp.ConsumeUnicode(max(0, fdp.remaining_bytes() // 2))
    for _ in range(depth):
        if fdp.ConsumeBool():
            key = fdp.ConsumeUnicode(max(0, fdp.remaining_bytes() // 4))
            obj = {key: obj}
        else:
            obj = [obj]

    original = deepcopy(obj)
    result = walk(obj)

    # Invariant: original is never mutated
    assert obj == original

    # Invariant: preserves top-level type
    assert type(result) is type(obj)

    # Invariant: all leaf strings satisfy clean() postconditions
    stack: list[object] = [result]
    seen: set[int] = set()
    while stack:
        item = stack.pop()
        obj_id = id(item)
        if obj_id in seen:
            continue
        if isinstance(item, str):
            assert "\x00" not in item
            assert not INVISIBLE_RE.search(item)
            assert not (set(item) & set(HOMOGLYPH_MAP))
            assert unicodedata.normalize("NFKC", item) == item
        elif isinstance(item, dict):
            seen.add(obj_id)
            stack.extend(item.values())
        elif isinstance(item, list):
            seen.add(obj_id)
            stack.extend(item)


_TARGETS = {
    "fuzz_clean": fuzz_clean,
    "fuzz_walk": fuzz_walk,
}


def main() -> None:
    target_name = "fuzz_clean"
    remaining_args = []
    for arg in sys.argv[1:]:
        if arg.startswith("--target="):
            target_name = arg.split("=", 1)[1]
        else:
            remaining_args.append(arg)

    target = _TARGETS.get(target_name)
    if target is None:
        print(
            f"Unknown target: {target_name!r}. Available: {list(_TARGETS)}",
            file=sys.stderr,
        )
        sys.exit(1)

    atheris.Setup([sys.argv[0], *remaining_args], target)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
