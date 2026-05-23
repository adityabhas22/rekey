"""Breach detection port."""

from __future__ import annotations

from typing import Protocol


class BreachChecker(Protocol):
    """Check whether a password has appeared in known breaches.

    Implementations should be privacy-preserving (e.g. k-anonymity range
    query against HIBP) so the full password never leaves the local process.
    """

    def count_breaches(self, password: str) -> int:
        """Return the number of times this password appears in known breaches.

        ``0`` = not found. Higher = more widely compromised.
        """
        ...
