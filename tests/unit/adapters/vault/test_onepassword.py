"""Tests for OnePasswordVault."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from rekey.adapters.vault.onepassword import OnePasswordError, OnePasswordVault, _OPRunner
from rekey.domain.credential import VaultSource
from rekey.ports.vault import CredentialNotFound


@pytest.fixture(autouse=True)
def _set_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "fake-test-token")


@pytest.fixture
def runner() -> MagicMock:
    return MagicMock(spec=_OPRunner)


class TestConstruction:
    def test_requires_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
        with pytest.raises(OnePasswordError, match="OP_SERVICE_ACCOUNT_TOKEN"):
            OnePasswordVault()

    def test_can_skip_token_check_for_tests(
        self,
        monkeypatch: pytest.MonkeyPatch,
        runner: MagicMock,
    ) -> None:
        monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
        OnePasswordVault(runner=runner, require_token=False)  # should not raise

    def test_name(self, runner: MagicMock) -> None:
        assert OnePasswordVault(runner=runner).name() == "1password"


class TestListCredentials:
    def test_parses_summary(self, runner: MagicMock) -> None:
        runner.run.return_value = json.dumps(
            [
                {
                    "id": "abc",
                    "title": "GitHub",
                    "category": "LOGIN",
                    "additional_information": "me@example.com",
                    "urls": [{"primary": True, "href": "https://github.com"}],
                },
                {
                    "id": "def",
                    "title": "Spotify",
                    "category": "LOGIN",
                    "additional_information": "me",
                    "urls": [{"primary": True, "href": "https://spotify.com/account"}],
                },
            ]
        )
        vault = OnePasswordVault(runner=runner)
        creds = vault.list_credentials()
        assert len(creds) == 2
        assert creds[0].id == "abc"
        assert creds[0].source == VaultSource.ONEPASSWORD
        assert creds[0].origin == "https://github.com"
        assert creds[0].username == "me@example.com"

    def test_skips_items_without_url(self, runner: MagicMock) -> None:
        runner.run.return_value = json.dumps(
            [
                {"id": "no-url", "title": "x", "category": "LOGIN", "urls": []},
                {
                    "id": "has-url",
                    "title": "GitHub",
                    "category": "LOGIN",
                    "urls": [{"primary": True, "href": "https://github.com"}],
                },
            ]
        )
        vault = OnePasswordVault(runner=runner)
        creds = vault.list_credentials()
        assert [c.id for c in creds] == ["has-url"]

    def test_invokes_op_correctly(self, runner: MagicMock) -> None:
        runner.run.return_value = "[]"
        OnePasswordVault(runner=runner).list_credentials()
        runner.run.assert_called_once_with(
            "item", "list", "--categories=Login", "--format=json"
        )


class TestGetPassword:
    def test_returns_password_value(self, runner: MagicMock) -> None:
        runner.run.return_value = json.dumps(
            {
                "id": "abc",
                "fields": [
                    {"id": "username", "value": "me@example.com"},
                    {"id": "password", "purpose": "PASSWORD", "value": "supersecret"},
                ],
            }
        )
        assert OnePasswordVault(runner=runner).get_password("abc") == "supersecret"

    def test_falls_back_to_id_when_purpose_missing(self, runner: MagicMock) -> None:
        runner.run.return_value = json.dumps(
            {
                "id": "abc",
                "fields": [
                    {"id": "password", "value": "pw"},
                ],
            }
        )
        assert OnePasswordVault(runner=runner).get_password("abc") == "pw"

    def test_raises_when_no_password_field(self, runner: MagicMock) -> None:
        runner.run.return_value = json.dumps({"id": "abc", "fields": []})
        with pytest.raises(CredentialNotFound):
            OnePasswordVault(runner=runner).get_password("abc")


class TestGetTOTP:
    def test_returns_code(self, runner: MagicMock) -> None:
        runner.run.return_value = "123456\n"
        assert OnePasswordVault(runner=runner).get_totp("abc") == "123456"

    def test_returns_none_on_error(self, runner: MagicMock) -> None:
        runner.run.side_effect = OnePasswordError("no otp configured")
        assert OnePasswordVault(runner=runner).get_totp("abc") is None

    def test_returns_none_on_empty_output(self, runner: MagicMock) -> None:
        runner.run.return_value = "\n"
        assert OnePasswordVault(runner=runner).get_totp("abc") is None


class TestUpdatePassword:
    def test_invokes_edit_with_assignment(self, runner: MagicMock) -> None:
        OnePasswordVault(runner=runner).update_password("abc", "newpw!@#")
        runner.run.assert_called_with("item", "edit", "abc", "password=newpw!@#")


class TestAppendNote:
    def test_appends_to_existing(self, runner: MagicMock) -> None:
        runner.run.side_effect = [
            json.dumps(
                {"id": "abc", "fields": [{"id": "notesPlain", "value": "old note"}]}
            ),
            "",  # edit returns nothing
        ]
        OnePasswordVault(runner=runner).append_note("abc", "rotated 2026-05-23")
        last_call = runner.run.call_args_list[-1]
        assert last_call.args[0:3] == ("item", "edit", "abc")
        assert last_call.args[3].startswith("notesPlain=")
        assert "old note" in last_call.args[3]
        assert "rotated 2026-05-23" in last_call.args[3]

    def test_creates_when_no_existing(self, runner: MagicMock) -> None:
        runner.run.side_effect = [
            json.dumps({"id": "abc", "fields": []}),
            "",
        ]
        OnePasswordVault(runner=runner).append_note("abc", "new note")
        last_call = runner.run.call_args_list[-1]
        assert last_call.args[3] == "notesPlain=new note"


class TestRunner:
    def test_missing_binary_raises_friendly_error(self) -> None:
        runner = _OPRunner(binary="nonexistent-binary-xyz")
        with pytest.raises(OnePasswordError, match="not found"):
            runner.run("item", "list")
