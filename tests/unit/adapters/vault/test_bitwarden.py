"""Tests for BitwardenVault."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock

import pytest

from rekey.adapters.vault.bitwarden import BitwardenError, BitwardenVault, _BWRunner
from rekey.domain.credential import VaultSource
from rekey.ports.vault import CredentialNotFound


@pytest.fixture(autouse=True)
def _set_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BW_SESSION", "fake-session-token")


@pytest.fixture
def runner() -> MagicMock:
    return MagicMock(spec=_BWRunner)


class TestConstruction:
    def test_requires_session(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BW_SESSION", raising=False)
        with pytest.raises(BitwardenError, match="BW_SESSION"):
            BitwardenVault()

    def test_can_skip_session_check(
        self,
        monkeypatch: pytest.MonkeyPatch,
        runner: MagicMock,
    ) -> None:
        monkeypatch.delenv("BW_SESSION", raising=False)
        BitwardenVault(runner=runner, require_session=False)

    def test_name(self, runner: MagicMock) -> None:
        assert BitwardenVault(runner=runner).name() == "bitwarden"


class TestListCredentials:
    def test_filters_to_login_type(self, runner: MagicMock) -> None:
        runner.run.return_value = json.dumps(
            [
                {
                    "id": "abc",
                    "name": "GitHub",
                    "type": 1,  # Login
                    "login": {
                        "username": "me",
                        "uris": [{"uri": "https://github.com"}],
                    },
                },
                {
                    "id": "note-id",
                    "name": "Secure Note",
                    "type": 2,  # Note — should be skipped
                    "notes": "secret stuff",
                },
            ]
        )
        creds = BitwardenVault(runner=runner).list_credentials()
        assert [c.id for c in creds] == ["abc"]
        assert creds[0].source == VaultSource.BITWARDEN
        assert creds[0].username == "me"

    def test_skips_login_without_uri(self, runner: MagicMock) -> None:
        runner.run.return_value = json.dumps(
            [
                {"id": "no-uri", "name": "x", "type": 1, "login": {"uris": []}},
                {
                    "id": "ok",
                    "name": "GitHub",
                    "type": 1,
                    "login": {"uris": [{"uri": "https://github.com"}]},
                },
            ]
        )
        creds = BitwardenVault(runner=runner).list_credentials()
        assert [c.id for c in creds] == ["ok"]

    def test_passes_session_arg(self, runner: MagicMock) -> None:
        runner.run.return_value = "[]"
        BitwardenVault(runner=runner).list_credentials()
        runner.run.assert_called_once_with("list", "items", "--session", "fake-session-token")


class TestGetPassword:
    def test_returns_password(self, runner: MagicMock) -> None:
        runner.run.return_value = json.dumps(
            {"id": "abc", "login": {"password": "secret"}}
        )
        assert BitwardenVault(runner=runner).get_password("abc") == "secret"

    def test_raises_when_missing(self, runner: MagicMock) -> None:
        runner.run.return_value = json.dumps({"id": "abc", "login": {}})
        with pytest.raises(CredentialNotFound):
            BitwardenVault(runner=runner).get_password("abc")


class TestGetTOTP:
    def test_returns_code(self, runner: MagicMock) -> None:
        runner.run.return_value = "987654\n"
        assert BitwardenVault(runner=runner).get_totp("abc") == "987654"

    def test_returns_none_on_error(self, runner: MagicMock) -> None:
        runner.run.side_effect = BitwardenError("not a TOTP item")
        assert BitwardenVault(runner=runner).get_totp("abc") is None


class TestUpdatePassword:
    def test_read_modify_write(self, runner: MagicMock) -> None:
        original = {"id": "abc", "type": 1, "login": {"password": "oldpw"}}
        runner.run.side_effect = [json.dumps(original), ""]
        BitwardenVault(runner=runner).update_password("abc", "newpw")

        edit_call = runner.run.call_args_list[-1]
        assert edit_call.args[0:3] == ("edit", "item", "abc")
        encoded = edit_call.args[3]
        # Last arg before --session/<token> should be the base64 payload
        decoded = json.loads(base64.b64decode(encoded).decode("utf-8"))
        assert decoded["login"]["password"] == "newpw"

    def test_creates_login_dict_if_missing(self, runner: MagicMock) -> None:
        runner.run.side_effect = [json.dumps({"id": "abc", "type": 1}), ""]
        BitwardenVault(runner=runner).update_password("abc", "newpw")
        edit_call = runner.run.call_args_list[-1]
        decoded = json.loads(base64.b64decode(edit_call.args[3]).decode("utf-8"))
        assert decoded["login"]["password"] == "newpw"


class TestAppendNote:
    def test_appends_to_existing_notes(self, runner: MagicMock) -> None:
        runner.run.side_effect = [
            json.dumps({"id": "abc", "type": 1, "notes": "first"}),
            "",
        ]
        BitwardenVault(runner=runner).append_note("abc", "second")
        edit_call = runner.run.call_args_list[-1]
        decoded = json.loads(base64.b64decode(edit_call.args[3]).decode("utf-8"))
        assert decoded["notes"] == "first\nsecond"


class TestRunner:
    def test_missing_binary_friendly_error(self) -> None:
        runner = _BWRunner(binary="nonexistent-binary-xyz")
        with pytest.raises(BitwardenError, match="not found"):
            runner.run("list", "items")
