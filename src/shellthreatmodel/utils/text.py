"""String utility helpers."""

from __future__ import annotations

import re

_SLUG_SAFE = re.compile(r"[^a-z0-9]+")


def slugify(value: str, *, default: str = "artifact") -> str:
    """Generate a filesystem-safe slug.

    This intentionally keeps things simple to avoid heavyweight dependencies.
    """

    value = value.lower().strip()
    slug = _SLUG_SAFE.sub("_", value)
    slug = slug.strip("_")
    return slug or default
