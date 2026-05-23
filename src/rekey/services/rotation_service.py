"""Rotation service — drives one credential's rotation lifecycle.

Workflow:

  1. Generate a new strong password (respecting policy).
  2. Stash secrets (current + new + expected origin) in the SecretStore for
     the custom browser actions to read.
  3. Delegate to the RotationDriver to navigate, fill, submit, resolve
     challenges, and verify on the site.
  4. On success: write the new password to the vault (preserving history),
     append a rotation note.
  5. On any failure: leave the vault untouched, record FAILED, clean up
     the SecretStore.

Every step transition emits an :class:`Event` to the configured
:class:`EventBus` so the web dashboard / CLI / logs can observe progress.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from rekey.adapters.browser.secret_store import RotationSecrets, SecretStore
from rekey.domain.credential import Credential
from rekey.domain.policy import PasswordPolicy
from rekey.domain.rotation import RotationAttempt, State
from rekey.ports.event_bus import EventBus
from rekey.ports.rotation_driver import LockoutDetected, RotationDriver
from rekey.ports.vault import VaultWriter
from rekey.services.password_generator import generate_password

logger = logging.getLogger(__name__)


PasswordGenerator = Callable[[PasswordPolicy | None], str]


def _default_generator(policy: PasswordPolicy | None) -> str:
    return generate_password(policy)


class RotationService:
    """Drive one credential's rotation lifecycle end-to-end."""

    def __init__(
        self,
        *,
        driver: RotationDriver,
        vault_writer: VaultWriter,
        secrets: SecretStore,
        event_bus: EventBus,
        password_generator: PasswordGenerator = _default_generator,
    ) -> None:
        self._driver = driver
        self._vault_writer = vault_writer
        self._secrets = secrets
        self._event_bus = event_bus
        self._generate = password_generator

    async def rotate(
        self,
        credential: Credential,
        current_password: str,
        *,
        policy: PasswordPolicy | None = None,
    ) -> RotationAttempt:
        """Run a complete rotation for one credential and return the final attempt."""
        attempt = RotationAttempt(credential_id=credential.composite_id)
        await self._emit(attempt, State.PENDING, f"starting rotation for {credential.host}")

        new_password = self._generate(policy)
        self._secrets.put(
            RotationSecrets(
                credential_id=credential.composite_id,
                expected_origin=credential.origin,
                current_password=current_password,
                new_password=new_password,
            )
        )

        try:
            await self._emit(
                attempt,
                State.FINDING_CHANGE_PAGE,
                "driver beginning navigation",
            )
            success = await self._driver.rotate(credential, new_password)
            if not success:
                await self._emit(attempt, State.FAILED, "driver reported failure")
                attempt.failure_reason = attempt.failure_reason or "driver returned False"
                return attempt

            await self._write_to_vault(credential, new_password, attempt)
            await self._emit(attempt, State.DONE, "rotation complete")
        except LockoutDetected as e:
            attempt.failure_reason = str(e) or "lockout detected"
            await self._emit(
                attempt, State.LOCKOUT_DETECTED, attempt.failure_reason,
            )
        except Exception as e:  # noqa: BLE001  capture-and-record at the boundary
            attempt.failure_reason = f"{type(e).__name__}: {e}"
            await self._emit(attempt, State.FAILED, attempt.failure_reason)
            logger.exception("Rotation failed for %s", credential.composite_id)
        finally:
            self._secrets.clear(credential.composite_id)

        return attempt

    async def _write_to_vault(
        self,
        credential: Credential,
        new_password: str,
        attempt: RotationAttempt,
    ) -> None:
        await self._emit(attempt, State.WRITING_TO_VAULT, "updating vault item")
        self._vault_writer.update_password(credential.id, new_password)
        try:
            note = f"Rotated by rekey on {datetime.now(UTC).isoformat()}"
            self._vault_writer.append_note(credential.id, note)
        except Exception as e:  # noqa: BLE001  note is best-effort
            logger.warning("Could not append rotation note: %s", e)
        attempt.new_password_set = True
        attempt.verified_login = True   # driver verified before returning True

    async def _emit(
        self,
        attempt: RotationAttempt,
        state: State,
        message: str,
        **data: Any,
    ) -> None:
        event = attempt.record(state, message, **data)
        await self._event_bus.publish(event)
