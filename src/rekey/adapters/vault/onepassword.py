"""1Password CLI adapter (`op`).

Auth via the ``OP_SERVICE_ACCOUNT_TOKEN`` env var. The token must be granted
*Read & Write* on every vault rekey will manage.

The adapter shells out to the ``op`` CLI rather than the Python SDK to avoid
SDK version churn — the CLI's JSON contract is stable.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any

from rekey.domain.credential import Credential, VaultSource
from rekey.ports.vault import CredentialNotFound


class OnePasswordError(Exception):
    """A 1Password CLI operation failed."""


@dataclass(frozen=True)
class _OPRunner:
    """Wraps ``op`` CLI invocations. Separable for testing."""

    binary: str = "op"

    def run(self, *args: str, input_: str | None = None) -> str:
        """Invoke ``op`` and return stdout. Raises :class:`OnePasswordError` on failure."""
        try:
            result = subprocess.run(
                [self.binary, *args],
                input=input_,
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError as e:
            raise OnePasswordError(
                "1Password CLI ('op') not found. Install from "
                "https://developer.1password.com/docs/cli/get-started/"
            ) from e
        except subprocess.CalledProcessError as e:
            raise OnePasswordError(
                f"op {' '.join(args)} failed (exit {e.returncode}): {e.stderr.strip()}"
            ) from e
        return result.stdout


def _primary_url(item: dict[str, Any]) -> str | None:
    urls = item.get("urls") or []
    primary = next((u.get("href") for u in urls if u.get("primary")), None)
    if primary:
        return primary
    return urls[0].get("href") if urls else None


class OnePasswordVault:
    """1Password vault adapter — implements VaultReader + VaultWriter."""

    def __init__(
        self,
        *,
        runner: _OPRunner | None = None,
        require_token: bool = True,
    ) -> None:
        self._runner = runner or _OPRunner()
        if require_token and "OP_SERVICE_ACCOUNT_TOKEN" not in os.environ:
            raise OnePasswordError(
                "OP_SERVICE_ACCOUNT_TOKEN is not set. Create a service-account "
                "token at https://my.1password.com/developer-tools/"
                "infrastructure-secrets/serviceaccount and export it."
            )

    def name(self) -> str:
        return "1password"

    def list_credentials(self) -> list[Credential]:
        """Enumerate Login items across vaults visible to the token."""
        raw = self._runner.run("item", "list", "--categories=Login", "--format=json")
        items = json.loads(raw or "[]")
        creds: list[Credential] = []
        for item in items:
            url = _primary_url(item)
            if not url:
                continue
            try:
                creds.append(
                    Credential.from_raw(
                        id=item["id"],
                        source=VaultSource.ONEPASSWORD,
                        origin=url,
                        username=item.get("additional_information") or "",
                        title=item.get("title"),
                        has_totp=False,  # list summary doesn't expose TOTP — fetch on demand
                    )
                )
            except (ValueError, KeyError):
                continue
        return creds

    def get_password(self, credential_id: str) -> str:
        raw = self._runner.run("item", "get", credential_id, "--format=json")
        item = json.loads(raw)
        for field in item.get("fields", []):
            if field.get("purpose") == "PASSWORD" or field.get("id") == "password":
                value = field.get("value")
                if value is not None:
                    return str(value)
        raise CredentialNotFound(credential_id)

    def get_totp(self, credential_id: str) -> str | None:
        try:
            output = self._runner.run("item", "get", credential_id, "--otp")
        except OnePasswordError:
            return None
        code = output.strip()
        return code or None

    def update_password(self, credential_id: str, new_password: str) -> None:
        """Update the password — 1Password preserves the previous value in item history."""
        self._runner.run("item", "edit", credential_id, f"password={new_password}")

    def append_note(self, credential_id: str, note: str) -> None:
        raw = self._runner.run("item", "get", credential_id, "--format=json")
        item = json.loads(raw)
        current = ""
        for field in item.get("fields", []):
            if field.get("id") == "notesPlain":
                current = field.get("value") or ""
                break
        combined = f"{current}\n{note}".strip() if current else note
        self._runner.run("item", "edit", credential_id, f"notesPlain={combined}")
