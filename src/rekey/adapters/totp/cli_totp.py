"""TOTP via the password-manager CLI.

When the credential has a TOTP secret stored in 1Password or Bitwarden,
this channel can generate the current 6-digit code with one CLI call.
Strictly better than reading email/SMS when available — deterministic,
offline, <100ms.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TOTPLookup:
    """How to look up a TOTP for one credential."""

    vault_source: str        # "1password" | "bitwarden"
    item_id: str             # adapter-native ID


class CLITOTPChannel:
    """Generate TOTPs by shelling out to ``op`` (1Password) or ``bw`` (Bitwarden).

    Used as a :class:`VerificationChannel` for 2FA prompts where the secret
    is stored in the user's vault.
    """

    def __init__(self, *, op_binary: str = "op", bw_binary: str = "bw") -> None:
        self._op = op_binary
        self._bw = bw_binary

    def code_for(self, lookup: TOTPLookup) -> str | None:
        """Return the current 6-digit TOTP, or ``None`` if not available."""
        if lookup.vault_source == "1password":
            return self._op_totp(lookup.item_id)
        if lookup.vault_source == "bitwarden":
            return self._bw_totp(lookup.item_id)
        logger.warning("CLITOTPChannel: unknown vault source %r", lookup.vault_source)
        return None

    # ---- internals ----

    def _op_totp(self, item_id: str) -> str | None:
        try:
            r = subprocess.run(
                [self._op, "item", "get", item_id, "--otp"],
                capture_output=True, text=True, check=True,
            )
        except FileNotFoundError:
            logger.debug("op CLI not found")
            return None
        except subprocess.CalledProcessError as e:
            logger.debug("op item get --otp failed for %s: %s", item_id, e.stderr.strip())
            return None
        code = r.stdout.strip()
        return code if code.isdigit() and 6 <= len(code) <= 8 else None

    def _bw_totp(self, item_id: str) -> str | None:
        import os
        session = os.environ.get("BW_SESSION")
        if not session:
            logger.debug("BW_SESSION not set; bw TOTP unavailable")
            return None
        try:
            r = subprocess.run(
                [self._bw, "get", "totp", item_id, "--session", session],
                capture_output=True, text=True, check=True,
            )
        except FileNotFoundError:
            logger.debug("bw CLI not found")
            return None
        except subprocess.CalledProcessError as e:
            logger.debug("bw get totp failed for %s: %s", item_id, e.stderr.strip())
            return None
        code = r.stdout.strip()
        return code if code.isdigit() and 6 <= len(code) <= 8 else None
