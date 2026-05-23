"""One-time-code / magic-link fetcher port."""

from __future__ import annotations

from typing import Protocol


class OTPFetcher(Protocol):
    """Retrieves a one-time code or reset link from the user's email."""

    async def fetch_code(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 120,
        digits: tuple[int, int] = (4, 8),
    ) -> str | None:
        """Wait for a relevant email and return its numeric code, or ``None``
        on timeout. ``digits`` is the (min, max) length range to match.
        """
        ...

    async def fetch_link(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 180,
    ) -> str | None:
        """Wait for a relevant email and return the first reset link, or
        ``None`` on timeout."""
        ...
