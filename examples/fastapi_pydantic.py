# ruff: noqa: RUF003
"""Sanitize user input at the edge of a FastAPI application.

Two patterns: Pydantic AfterValidator for model fields, and FastAPI Depends
for query parameters. Both ensure every string is sanitized before your
application logic sees it.

Usage:
    python examples/fastapi_pydantic.py

Note: This is a standalone demo. Install fastapi and pydantic to see
the full integration patterns; the script runs without them too.
"""

from __future__ import annotations

from typing import Annotated

from navi_sanitize import clean, jinja2_escaper

# --- Pydantic pattern: AfterValidator ---
# Every SafeStr field is automatically sanitized on model creation.

try:
    from pydantic import AfterValidator, BaseModel

    SafeStr = Annotated[str, AfterValidator(clean)]

    class UserProfile(BaseModel):
        name: SafeStr
        bio: SafeStr

    # Cyrillic homoglyphs in name, zero-width space in bio
    profile = UserProfile(
        name="J\u043ehn D\u043ee",  # Cyrillic о (U+043E)
        bio="Hello\u200b world\u200c!",  # zero-width space + non-joiner
    )
    print("=== Pydantic AfterValidator ===")
    print(f"  name: {profile.name!r}")  # 'John Doe'
    print(f"  bio:  {profile.bio!r}")  # 'Hello world!'
    print()

except ImportError:
    print("(Skipping Pydantic demo — install pydantic to see it)\n")


# --- FastAPI pattern: Depends ---
# Sanitize query params before they reach your endpoint.

try:
    from fastapi import Depends, FastAPI, Query

    app = FastAPI()

    def safe_query(q: str = Query()) -> str:
        return clean(q, escaper=jinja2_escaper)

    @app.get("/search")
    def search(q: str = Depends(safe_query)):
        return {"query": q}

    # Simulate a request
    result = safe_query("{{ c\u043enfig.__class__ }}")  # Cyrillic о + Jinja2 SSTI
    print("=== FastAPI Depends ===")
    print("  input:  '{{ c\\u043enfig.__class__ }}'")
    print(f"  output: {result!r}")
    print()

except ImportError:
    print("(Skipping FastAPI demo — install fastapi to see it)\n")


# --- Standalone demo (no dependencies needed) ---
print("=== Standalone (no dependencies needed) ===")
demos = [
    ("homoglyph phishing", "p\u0430ypal.com", clean("p\u0430ypal.com")),
    ("null byte injection", "admin\\x00.jpg", clean("admin\x00.jpg")),
    (
        "fullwidth bypass",
        "\\uff41\\uff44\\uff4d\\uff49\\uff4e",
        clean("\uff41\uff44\uff4d\uff49\uff4e"),
    ),
    ("jinja2 SSTI", "{{ config }}", clean("{{ config }}", escaper=jinja2_escaper)),
]
for label, _raw, result in demos:
    print(f"  {label}: {result!r}")
