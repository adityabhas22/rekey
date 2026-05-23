"""HIBP Pwned Passwords range API adapter — privacy-preserving via k-anonymity."""

from __future__ import annotations

import hashlib
from typing import Self

import httpx

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


class HIBPChecker:
    """Breach check via HIBP's k-anonymity range API.

    The client sends only the first 5 hex chars of ``SHA-1(password)`` and
    receives all suffixes that share that prefix. The full password never
    leaves the local process.

    Implements the :class:`rekey.ports.BreachChecker` protocol.

    Usage::

        with HIBPChecker() as checker:
            n = checker.count_breaches("password")
    """

    def __init__(
        self,
        *,
        timeout: float = 5.0,
        add_padding: bool = True,
        client: httpx.Client | None = None,
    ) -> None:
        self._timeout = timeout
        self._add_padding = add_padding
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=timeout,
            headers={"User-Agent": "rekey-credential-hygiene/0.1"},
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def count_breaches(self, password: str) -> int:
        """Return how many times this password appears in HIBP's corpus.

        Returns 0 for empty passwords or those not found in any known breach.
        Raises ``httpx.HTTPStatusError`` if the HIBP API returns a non-2xx
        status (e.g. rate-limited).
        """
        if not password:
            return 0
        digest = hashlib.sha1(  # noqa: S324  HIBP identifier, not crypto integrity
            password.encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        headers = {"Add-Padding": "true"} if self._add_padding else {}
        response = self._client.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers=headers,
        )
        response.raise_for_status()
        for line in response.text.splitlines():
            parts = line.strip().split(":")
            if len(parts) != 2:
                continue
            line_suffix, count = parts
            if line_suffix.strip() == suffix:
                try:
                    return int(count)
                except ValueError:
                    return 0
        return 0
