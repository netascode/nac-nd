"""Simple progress lines for interactive CLI use."""

from __future__ import annotations

import sys


def note(message: str) -> None:
    """Write a short progress update to stderr."""
    print(message, file=sys.stderr, flush=True)
