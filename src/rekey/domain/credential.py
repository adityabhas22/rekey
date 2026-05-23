"""Credential domain model — a vault item (without the password value)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from urllib.parse import urlparse


class VaultSource(StrEnum):
    """Identifier for the vault adapter a credential originated from."""

    ONEPASSWORD = "1password"
    BITWARDEN = "bitwarden"
    CSV_APPLE = "csv:apple"
    CSV_CHROME = "csv:chrome"
    CSV_FIREFOX = "csv:firefox"
    CSV_GENERIC = "csv:generic"


def canonical_origin(url_or_host: str) -> str:
    """Normalize a URL or host into canonical ``https://host`` form.

    Strips path, query, fragment, and default ports; lowercases the host.
    Treats bare hostnames as https.
    """
    s = url_or_host.strip()
    if not s:
        raise ValueError("origin cannot be empty")
    if "://" not in s:
        s = f"https://{s}"
    parsed = urlparse(s)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(f"cannot derive host from {url_or_host!r}")
    scheme = parsed.scheme or "https"
    return f"{scheme}://{host}"


@dataclass(frozen=True, slots=True)
class Credential:
    """A login vault item.

    The password value is intentionally NOT held here — adapters fetch it on
    demand via ``VaultReader.get_password`` so secrets are not retained in
    long-lived in-memory objects.

    The constructor is strict: ``origin`` must already be canonical. Use
    :meth:`Credential.from_raw` for inputs that may not be canonical.
    """

    id: str
    source: VaultSource
    origin: str
    username: str
    title: str | None = None
    has_totp: bool = False
    last_changed: datetime | None = None
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Credential.id must be non-empty")
        if not self.origin:
            raise ValueError("Credential.origin must be non-empty")
        expected = canonical_origin(self.origin)
        if expected != self.origin:
            raise ValueError(
                f"Credential.origin must be canonical; got {self.origin!r}, "
                f"expected {expected!r}. Use Credential.from_raw() for raw input."
            )

    @classmethod
    def from_raw(
        cls,
        *,
        id: str,
        source: VaultSource,
        origin: str,
        username: str,
        title: str | None = None,
        has_totp: bool = False,
        last_changed: datetime | None = None,
        tags: tuple[str, ...] = (),
    ) -> Credential:
        """Construct from possibly-non-canonical inputs (URLs with paths, mixed case).

        Used by adapters when importing from external sources.
        """
        return cls(
            id=id,
            source=source,
            origin=canonical_origin(origin),
            username=username,
            title=title,
            has_totp=has_totp,
            last_changed=last_changed,
            tags=tags,
        )

    @property
    def host(self) -> str:
        """Hostname without scheme — for display purposes."""
        return urlparse(self.origin).hostname or self.origin

    @property
    def composite_id(self) -> str:
        """Globally-unique identifier across all vault sources."""
        return f"{self.source.value}::{self.id}"
