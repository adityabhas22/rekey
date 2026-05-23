"""Composition root tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from rekey.composition import (
    NoVaultsConfigured,
    NoVaultWriter,
    build_audit_dependencies,
    build_rotation_dependencies,
)
from rekey.config import Settings


class FakeChecker:
    def count_breaches(self, password: str) -> int:
        return 0


def _csv_with(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


class TestAuditDependencies:
    def test_csv_only_works(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Remove live vault env vars
        monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
        monkeypatch.delenv("BW_SESSION", raising=False)
        csv_path = _csv_with(
            tmp_path / "x.csv",
            "URL,Username,Password\nhttps://github.com,me,password\n",
        )
        settings = Settings(csv_paths=str(csv_path))
        deps = build_audit_dependencies(settings, breach_checker=FakeChecker())
        assert len(deps.vaults) == 1
        findings = deps.audit_service.run()
        assert len(findings) == 1
        # "password" is in our common-password dictionary → flagged WEAK
        assert any(i.kind.value == "weak" for i in findings[0].issues)

    def test_no_vaults_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
        monkeypatch.delenv("BW_SESSION", raising=False)
        with pytest.raises(NoVaultsConfigured):
            build_audit_dependencies(Settings(csv_paths=""))


class TestRotationDependencies:
    def test_csv_only_raises_no_writer(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
        monkeypatch.delenv("BW_SESSION", raising=False)
        csv_path = _csv_with(
            tmp_path / "x.csv",
            "URL,Username,Password\nhttps://github.com,me,p\n",
        )
        with pytest.raises(NoVaultWriter):
            build_rotation_dependencies(Settings(csv_paths=str(csv_path)))
