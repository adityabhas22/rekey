"""Smoke tests for the Typer CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from rekey.cli import app

runner = CliRunner()


class TestHelp:
    def test_root_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "rekey" in result.stdout.lower()
        assert "audit" in result.stdout.lower()
        assert "rotate" in result.stdout.lower()

    def test_audit_help(self) -> None:
        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0
        assert "audit" in result.stdout.lower()

    def test_rotate_help(self) -> None:
        result = runner.invoke(app, ["rotate", "--help"])
        assert result.exit_code == 0
        assert "rotate" in result.stdout.lower()


class TestAuditNoVaults:
    def test_exits_with_friendly_error_when_no_vaults(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
        monkeypatch.delenv("BW_SESSION", raising=False)
        monkeypatch.delenv("REKEY_CSV_PATHS", raising=False)
        result = runner.invoke(app, ["audit"])
        assert result.exit_code == 2
        # Output goes through rich; we just check it didn't crash uncleanly.


class TestAuditCSV:
    def test_audit_with_csv(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
        monkeypatch.delenv("BW_SESSION", raising=False)

        csv_path = tmp_path / "passwords.csv"
        csv_path.write_text(
            "URL,Username,Password\n"
            "https://github.com,me,Tnv8k!XyW2gqMpL3aZ#%\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("REKEY_CSV_PATHS", str(csv_path))

        # Inject a fake breach checker via a monkey-patched factory
        from rekey import composition as comp

        class _FakeChecker:
            def count_breaches(self, password: str) -> int:
                return 0

        original_build = comp.build_audit_dependencies

        def _build_with_fake(settings=None, **kw):
            return original_build(settings, breach_checker=_FakeChecker())

        monkeypatch.setattr(comp, "build_audit_dependencies", _build_with_fake)
        # Re-import in cli module since we already imported the symbol
        from rekey import cli

        monkeypatch.setattr(cli, "build_audit_dependencies", _build_with_fake)

        out_path = tmp_path / "results.json"
        result = runner.invoke(app, ["audit", "--output", str(out_path), "--quiet"])
        assert result.exit_code == 0
        assert out_path.exists()
        import json

        data = json.loads(out_path.read_text())
        assert len(data) == 1
        assert data[0]["credential"]["host"] == "github.com"
