"""Tests for the CSV import vault adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from rekey.adapters.vault.csv_import import CSVImportVault
from rekey.domain.credential import VaultSource
from rekey.ports.vault import CredentialNotFound


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    lines = [",".join(header)]
    for row in rows:
        # Trivial CSV quoting — none of our test data needs it.
        lines.append(",".join(row))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestAppleFormat:
    def test_basic_import(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "apple.csv"
        _write_csv(
            csv_path,
            ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"],
            [
                ["GitHub", "https://github.com", "me@example.com", "supersecret", "", ""],
                ["Spotify", "https://spotify.com/account", "me", "xyz", "", ""],
            ],
        )
        vault = CSVImportVault(csv_path, source=VaultSource.CSV_APPLE)
        creds = vault.list_credentials()
        assert len(creds) == 2
        github = next(c for c in creds if c.host == "github.com")
        assert github.source == VaultSource.CSV_APPLE
        assert github.origin == "https://github.com"
        assert github.username == "me@example.com"
        assert vault.get_password(github.id) == "supersecret"


class TestChromeFormat:
    def test_lowercase_headers(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "chrome.csv"
        _write_csv(
            csv_path,
            ["name", "url", "username", "password", "note"],
            [["GitHub", "https://github.com", "u", "p", ""]],
        )
        vault = CSVImportVault(csv_path, source=VaultSource.CSV_CHROME)
        creds = vault.list_credentials()
        assert len(creds) == 1
        assert vault.get_password(creds[0].id) == "p"


class TestErrorHandling:
    def test_missing_file(self, tmp_path: Path) -> None:
        vault = CSVImportVault(tmp_path / "missing.csv")
        with pytest.raises(FileNotFoundError):
            vault.list_credentials()

    def test_rows_without_url_skipped(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "x.csv"
        _write_csv(
            csv_path,
            ["URL", "Username", "Password"],
            [
                ["", "u", "p"],            # missing URL — skip
                ["https://ok.com", "u", "p"],
            ],
        )
        vault = CSVImportVault(csv_path)
        assert len(vault.list_credentials()) == 1

    def test_rows_without_password_skipped(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "x.csv"
        _write_csv(
            csv_path,
            ["URL", "Username", "Password"],
            [
                ["https://ok.com", "u", ""],
                ["https://ok2.com", "u", "p"],
            ],
        )
        vault = CSVImportVault(csv_path)
        assert len(vault.list_credentials()) == 1

    def test_get_password_unknown_id(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "x.csv"
        _write_csv(
            csv_path,
            ["URL", "Password"],
            [["https://ok.com", "p"]],
        )
        vault = CSVImportVault(csv_path)
        vault.list_credentials()
        with pytest.raises(CredentialNotFound):
            vault.get_password("nonexistent-id")


class TestIdempotency:
    def test_ids_stable_across_loads(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "x.csv"
        _write_csv(
            csv_path,
            ["URL", "Username", "Password"],
            [["https://github.com", "me", "p"]],
        )
        a = CSVImportVault(csv_path).list_credentials()[0].id
        b = CSVImportVault(csv_path).list_credentials()[0].id
        assert a == b


class TestTOTP:
    def test_returns_none_when_no_secret(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "x.csv"
        _write_csv(
            csv_path,
            ["URL", "Password"],
            [["https://ok.com", "p"]],
        )
        vault = CSVImportVault(csv_path)
        cred = vault.list_credentials()[0]
        assert vault.get_totp(cred.id) is None

    def test_generates_code_from_otpauth_uri(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "x.csv"
        _write_csv(
            csv_path,
            ["URL", "Password", "OTPAuth"],
            [["https://ok.com", "p", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=test"]],
        )
        vault = CSVImportVault(csv_path)
        cred = vault.list_credentials()[0]
        code = vault.get_totp(cred.id)
        assert code is not None
        assert code.isdigit()
        assert len(code) == 6
