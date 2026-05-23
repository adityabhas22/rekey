"""CSV-import vault adapter — read-only, for Apple Passwords / Chrome / Firefox / generic exports.

SECURITY: CSV exports contain plaintext passwords. The caller is responsible
for protecting the file (encrypted volume, delete after import).
"""

from __future__ import annotations

import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pyotp

from rekey.domain.credential import Credential, VaultSource
from rekey.ports.vault import CredentialNotFound

# Map of our normalized field names to the column-name variants we accept,
# covering Apple Passwords, Chrome, Firefox, 1Password and Bitwarden CSV exports.
_FIELD_VARIANTS: Final[dict[str, frozenset[str]]] = {
    "title": frozenset({"title", "name", "label"}),
    "url": frozenset({"url", "uri", "website", "address", "login_uri"}),
    "username": frozenset(
        {"username", "user", "login", "email", "login_username", "user name"}
    ),
    "password": frozenset({"password", "pass", "pwd", "login_password"}),
    "totp": frozenset({"totp", "otpauth", "otp_secret", "otpauth_url", "login_totp"}),
    "notes": frozenset({"notes", "note", "comment"}),
}


def _make_id(url: str, username: str) -> str:
    """Stable ID derived from URL + username so re-imports are idempotent."""
    digest = hashlib.sha256(f"{url}|{username}".encode()).hexdigest()
    return f"csv-{digest[:16]}"


@dataclass(frozen=True, slots=True)
class _CSVItem:
    """One parsed CSV row paired with secret material kept inside the adapter."""

    credential: Credential
    password: str
    totp_secret: str | None


def _build_field_mapping(fieldnames: list[str]) -> dict[str, str | None]:
    """Map each normalized field to the actual column name in the CSV, if any."""
    actual = {col.lower().strip(): col for col in fieldnames}
    mapping: dict[str, str | None] = {}
    for normalized, variants in _FIELD_VARIANTS.items():
        match = next((actual[v] for v in variants if v in actual), None)
        mapping[normalized] = match
    return mapping


def _row_to_item(
    row: dict[str, str],
    mapping: dict[str, str | None],
    source: VaultSource,
) -> _CSVItem | None:
    """Convert a CSV row to an item, or None if the row is unusable."""

    def field(name: str) -> str | None:
        col = mapping.get(name)
        if not col:
            return None
        value = (row.get(col) or "").strip()
        return value or None

    url = field("url")
    password = field("password")
    if not url or not password:
        return None  # need at least URL and password to be useful

    username = field("username") or ""
    try:
        credential = Credential.from_raw(
            id=_make_id(url, username),
            source=source,
            origin=url,
            username=username,
            title=field("title"),
            has_totp=bool(field("totp")),
        )
    except ValueError:
        return None

    return _CSVItem(
        credential=credential,
        password=password,
        totp_secret=field("totp"),
    )


class CSVImportVault:
    """Read-only :class:`rekey.ports.VaultReader` over a CSV password export."""

    def __init__(
        self,
        path: Path | str,
        *,
        source: VaultSource = VaultSource.CSV_GENERIC,
    ) -> None:
        self._path = Path(path)
        self._source = source
        self._items: dict[str, _CSVItem] = {}
        self._loaded = False

    def name(self) -> str:
        return f"csv:{self._path.name}"

    def list_credentials(self) -> list[Credential]:
        self._load()
        return [item.credential for item in self._items.values()]

    def get_password(self, credential_id: str) -> str:
        self._load()
        item = self._require(credential_id)
        return item.password

    def get_totp(self, credential_id: str) -> str | None:
        self._load()
        item = self._require(credential_id)
        if not item.totp_secret:
            return None
        try:
            if item.totp_secret.startswith("otpauth://"):
                otp = pyotp.parse_uri(item.totp_secret)
            else:
                otp = pyotp.TOTP(item.totp_secret)
            return otp.now()
        except (ValueError, Exception):  # noqa: BLE001  parse errors → no TOTP
            return None

    def _load(self) -> None:
        if self._loaded:
            return
        if not self._path.exists():
            raise FileNotFoundError(f"CSV not found: {self._path}")
        with self._path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            mapping = _build_field_mapping(list(reader.fieldnames or []))
            for row in reader:
                item = _row_to_item(row, mapping, self._source)
                if item is None:
                    continue
                self._items[item.credential.id] = item
        self._loaded = True

    def _require(self, credential_id: str) -> _CSVItem:
        item = self._items.get(credential_id)
        if item is None:
            raise CredentialNotFound(credential_id)
        return item
