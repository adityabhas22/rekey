"""Bitwarden CLI adapter (`bw`).

Auth via the ``BW_SESSION`` env var. The user must run::

    bw login
    export BW_SESSION="$(bw unlock --raw)"

Bitwarden's CLI requires updates to be sent as base64-encoded JSON, so writes
are read-modify-write: fetch the item, mutate, base64-encode, ``bw edit``.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any

from rekey.domain.credential import Credential, VaultSource
from rekey.ports.vault import CredentialNotFound

_LOGIN_TYPE = 1   # Bitwarden item type for Login items


class BitwardenError(Exception):
    """A Bitwarden CLI operation failed."""


@dataclass(frozen=True)
class _BWRunner:
    """Wraps ``bw`` CLI invocations. Separable for testing."""

    binary: str = "bw"

    def run(self, *args: str) -> str:
        try:
            result = subprocess.run(
                [self.binary, *args],
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError as e:
            raise BitwardenError(
                "Bitwarden CLI ('bw') not found. Install from "
                "https://bitwarden.com/help/cli/"
            ) from e
        except subprocess.CalledProcessError as e:
            raise BitwardenError(
                f"bw {' '.join(args)} failed (exit {e.returncode}): {e.stderr.strip()}"
            ) from e
        return result.stdout


class BitwardenVault:
    """Bitwarden vault adapter — implements VaultReader + VaultWriter."""

    def __init__(
        self,
        *,
        runner: _BWRunner | None = None,
        require_session: bool = True,
    ) -> None:
        self._runner = runner or _BWRunner()
        self._session = os.environ.get("BW_SESSION")
        if require_session and not self._session:
            raise BitwardenError(
                "BW_SESSION is not set. Run `bw login && bw unlock --raw` and "
                "export the session token."
            )

    def name(self) -> str:
        return "bitwarden"

    def list_credentials(self) -> list[Credential]:
        items = json.loads(self._run_with_session("list", "items") or "[]")
        creds: list[Credential] = []
        for item in items:
            if item.get("type") != _LOGIN_TYPE:
                continue
            login = item.get("login") or {}
            uris = login.get("uris") or []
            primary_uri = uris[0].get("uri") if uris else None
            if not primary_uri:
                continue
            try:
                creds.append(
                    Credential.from_raw(
                        id=item["id"],
                        source=VaultSource.BITWARDEN,
                        origin=primary_uri,
                        username=login.get("username") or "",
                        title=item.get("name"),
                        has_totp=bool(login.get("totp")),
                    )
                )
            except (ValueError, KeyError):
                continue
        return creds

    def get_password(self, credential_id: str) -> str:
        item = self._get_item(credential_id)
        password = (item.get("login") or {}).get("password")
        if password is None:
            raise CredentialNotFound(credential_id)
        return str(password)

    def get_totp(self, credential_id: str) -> str | None:
        try:
            output = self._run_with_session("get", "totp", credential_id)
        except BitwardenError:
            return None
        code = output.strip()
        return code or None

    def update_password(self, credential_id: str, new_password: str) -> None:
        item = self._get_item(credential_id)
        item.setdefault("login", {})["password"] = new_password
        self._edit_item(credential_id, item)

    def append_note(self, credential_id: str, note: str) -> None:
        item = self._get_item(credential_id)
        existing = item.get("notes") or ""
        item["notes"] = f"{existing}\n{note}".strip() if existing else note
        self._edit_item(credential_id, item)

    # ------ internals ------

    def _run_with_session(self, *args: str) -> str:
        if not self._session:
            raise BitwardenError("BW_SESSION not available")
        return self._runner.run(*args, "--session", self._session)

    def _get_item(self, credential_id: str) -> dict[str, Any]:
        raw = self._run_with_session("get", "item", credential_id)
        return json.loads(raw)  # type: ignore[no-any-return]

    def _edit_item(self, credential_id: str, item: dict[str, Any]) -> None:
        payload = base64.b64encode(json.dumps(item).encode("utf-8")).decode("ascii")
        self._run_with_session("edit", "item", credential_id, payload)
