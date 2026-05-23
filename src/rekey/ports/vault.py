"""Vault read/write ports.

Split per Interface Segregation Principle: read-only adapters (e.g. CSV
import) implement only :class:`VaultReader`. The audit service only needs
``VaultReader``; the rotation service needs both.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from rekey.domain.credential import Credential


class CredentialNotFound(Exception):
    """Raised when a credential ID is not present in the vault."""


@runtime_checkable
class VaultReader(Protocol):
    """Read access to a credential store."""

    def name(self) -> str:
        """Short identifier for logs/UI (e.g. ``"1password"``)."""
        ...

    def list_credentials(self) -> list[Credential]:
        """Enumerate login items. Password values are NOT included here."""
        ...

    def get_password(self, credential_id: str) -> str:
        """Read the current password. Raises :class:`CredentialNotFound` if missing."""
        ...

    def get_totp(self, credential_id: str) -> str | None:
        """Return current 6-digit TOTP if a secret is stored, else ``None``."""
        ...


@runtime_checkable
class VaultWriter(Protocol):
    """Write access to a credential store."""

    def name(self) -> str: ...

    def update_password(self, credential_id: str, new_password: str) -> None:
        """Update the password. Implementations MUST preserve the previous value
        in the item's native history (1Password and Bitwarden do this natively)."""
        ...

    def append_note(self, credential_id: str, note: str) -> None:
        """Append an audit/rotation note to the item."""
        ...
