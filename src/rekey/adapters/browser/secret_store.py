"""Per-rotation secret material — kept out of the LLM's context.

The :class:`SecretStore` holds passwords and origin-validation data for the
duration of a rotation. The custom browser actions read from here when
typing into fields, so the secret values never appear in any string the
LLM sees.
"""

from __future__ import annotations

from dataclasses import dataclass


class SecretNotFound(KeyError):
    """No secrets registered for this credential_id (yet, or already cleared)."""


@dataclass(frozen=True, slots=True)
class RotationSecrets:
    """All the secret material a single rotation needs."""

    credential_id: str
    expected_origin: str        # canonical https://host — used to validate page before typing
    current_password: str
    new_password: str


class SecretStore:
    """In-memory secret registry — per-rotation entries live here transiently.

    The orchestrator populates this before launching the browser agent and
    clears it after the rotation completes or fails.
    """

    def __init__(self) -> None:
        self._records: dict[str, RotationSecrets] = {}

    def put(self, secrets: RotationSecrets) -> None:
        self._records[secrets.credential_id] = secrets

    def get(self, credential_id: str) -> RotationSecrets:
        try:
            return self._records[credential_id]
        except KeyError as e:
            raise SecretNotFound(credential_id) from e

    def clear(self, credential_id: str) -> None:
        self._records.pop(credential_id, None)

    def clear_all(self) -> None:
        self._records.clear()

    def __contains__(self, credential_id: object) -> bool:
        return credential_id in self._records

    def __len__(self) -> int:
        return len(self._records)
