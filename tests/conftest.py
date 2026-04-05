# SPDX-License-Identifier: MIT
"""Shared pytest configuration and hypothesis profiles."""

from __future__ import annotations

from hypothesis import HealthCheck, settings

# dev: fast feedback (default profile, used by `uv run pytest`)
settings.register_profile(
    "dev",
    max_examples=50,
    suppress_health_check=[HealthCheck.too_slow],
)

# ci: thorough (used by CI with --hypothesis-profile=ci)
settings.register_profile(
    "ci",
    max_examples=500,
    suppress_health_check=[HealthCheck.too_slow],
)

# security: exhaustive (manual runs for release validation)
settings.register_profile(
    "security",
    max_examples=10000,
    suppress_health_check=[HealthCheck.too_slow],
)

settings.load_profile("dev")
