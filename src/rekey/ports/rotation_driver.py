"""High-level browser driver — performs the per-site rotation work."""

from __future__ import annotations

from typing import Protocol

from rekey.domain.credential import Credential


class RotationDriverError(Exception):
    """Driver-level failure that the orchestrator should record as FAILED."""


class LockoutDetected(RotationDriverError):
    """The driver saw a lockout / step-up barrier and aborted.

    The orchestrator must NEVER retry after this signal.
    """


class RotationDriver(Protocol):
    """Performs a single credential rotation end-to-end on the live site.

    Implementations wrap a browser agent (e.g. ``browser-use``) plus the
    custom secret-typing actions. They navigate, fill, submit, resolve
    in-flow challenges (auto for TOTP/email; via :class:`HandoffUI` for
    SMS/push/CAPTCHA), and verify the change took on the site.

    Writing the new password back to the vault is the orchestrator's
    responsibility, not the driver's.
    """

    async def rotate(
        self,
        credential: Credential,
        new_password: str,
    ) -> bool:
        """Run the rotation on the live site.

        Returns ``True`` if the site indicated the password was successfully
        changed. Raises :class:`LockoutDetected` if the page showed a lockout
        or fraud-challenge barrier (do not retry).
        """
        ...
