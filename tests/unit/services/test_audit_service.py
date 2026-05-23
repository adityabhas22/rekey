"""Tests for AuditService."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from rekey.domain.audit import IssueKind, Severity
from rekey.domain.credential import Credential, VaultSource
from rekey.services.audit_service import AuditService


# ---- Fakes -------------------------------------------------------------


@dataclass
class FakeVault:
    """Test double for VaultReader."""

    label: str
    items: dict[str, tuple[Credential, str]] = field(default_factory=dict)

    def name(self) -> str:
        return self.label

    def list_credentials(self) -> list[Credential]:
        return [c for c, _ in self.items.values()]

    def get_password(self, credential_id: str) -> str:
        return self.items[credential_id][1]

    def get_totp(self, credential_id: str) -> str | None:
        return None


class FakeBreachChecker:
    def __init__(self, breaches: dict[str, int] | None = None) -> None:
        self._breaches = breaches or {}

    def count_breaches(self, password: str) -> int:
        return self._breaches.get(password, 0)


class FailingBreachChecker:
    def count_breaches(self, password: str) -> int:
        raise RuntimeError("network down")


def _cred(
    id_: str,
    source: VaultSource = VaultSource.ONEPASSWORD,
    host: str = "site.com",
) -> Credential:
    return Credential(
        id=id_,
        source=source,
        origin=f"https://{host}",
        username="me",
    )


# ---- Tests -------------------------------------------------------------


class TestConstruction:
    def test_requires_at_least_one_vault(self) -> None:
        with pytest.raises(ValueError, match="at least one vault"):
            AuditService(vaults=[], breach_checker=FakeBreachChecker())


class TestEmpty:
    def test_empty_vault(self) -> None:
        svc = AuditService(vaults=[FakeVault("v")], breach_checker=FakeBreachChecker())
        assert svc.run() == []


class TestCompromise:
    def test_widely_compromised_is_critical(self) -> None:
        c = _cred("c1")
        vault = FakeVault("v", {"c1": (c, "compromised-pw")})
        breach = FakeBreachChecker({"compromised-pw": 50000})
        findings = AuditService(vaults=[vault], breach_checker=breach).run()
        assert len(findings) == 1
        issue = next(i for i in findings[0].issues if i.kind == IssueKind.COMPROMISED)
        assert issue.severity == Severity.CRITICAL
        assert issue.metric == 50000

    def test_lightly_compromised_is_high(self) -> None:
        c = _cred("c1")
        vault = FakeVault("v", {"c1": (c, "lightly-pw")})
        breach = FakeBreachChecker({"lightly-pw": 5})
        findings = AuditService(vaults=[vault], breach_checker=breach).run()
        issue = next(i for i in findings[0].issues if i.kind == IssueKind.COMPROMISED)
        assert issue.severity == Severity.HIGH


class TestWeakness:
    def test_weak_password_flagged(self) -> None:
        c = _cred("c1")
        vault = FakeVault("v", {"c1": (c, "password")})
        findings = AuditService(vaults=[vault], breach_checker=FakeBreachChecker()).run()
        assert any(i.kind == IssueKind.WEAK for i in findings[0].issues)


class TestReuse:
    def test_two_creds_same_password_both_flagged(self) -> None:
        c1 = _cred("c1", host="a.com")
        c2 = _cred("c2", host="b.com")
        vault = FakeVault(
            "v",
            {
                "c1": (c1, "shared-strong-pw-XyZ!2$%"),
                "c2": (c2, "shared-strong-pw-XyZ!2$%"),
            },
        )
        findings = AuditService(vaults=[vault], breach_checker=FakeBreachChecker()).run()
        assert len(findings) == 2
        for f in findings:
            assert any(i.kind == IssueKind.REUSED for i in f.issues)


class TestMultiVault:
    def test_composite_ids_disambiguate(self) -> None:
        c1 = _cred("same-id", VaultSource.ONEPASSWORD, "a.com")
        c2 = _cred("same-id", VaultSource.BITWARDEN, "b.com")
        v1 = FakeVault("1p", {"same-id": (c1, "Tnv8k!XyW2gqMpL3aZ#")})
        v2 = FakeVault("bw", {"same-id": (c2, "different-strong-PW-xY9!")})
        findings = AuditService(vaults=[v1, v2], breach_checker=FakeBreachChecker()).run()
        ids = {f.credential.composite_id for f in findings}
        assert ids == {"1password::same-id", "bitwarden::same-id"}


class TestSorting:
    def test_sorted_by_priority_desc(self) -> None:
        critical = _cred("crit", host="critical.com")
        clean = _cred("clean", host="clean.com")
        vault = FakeVault(
            "v",
            {
                "crit": (critical, "password"),   # weak + compromised
                "clean": (clean, "Tnv8k!XyW2gqMpL3aZ#"),
            },
        )
        breach = FakeBreachChecker({"password": 100000})
        findings = AuditService(vaults=[vault], breach_checker=breach).run()
        assert findings[0].credential.host == "critical.com"
        assert findings[-1].credential.host == "clean.com"
        assert findings[-1].is_clean


class TestResilience:
    def test_password_fetch_error_skips_that_credential(self) -> None:
        c1 = _cred("c1", host="a.com")
        c2 = _cred("c2", host="b.com")

        class FlakyVault:
            def name(self) -> str:
                return "flaky"

            def list_credentials(self) -> list[Credential]:
                return [c1, c2]

            def get_password(self, credential_id: str) -> str:
                if credential_id == "c1":
                    raise RuntimeError("simulated failure")
                return "Tnv8k!XyW2gqMpL3aZ#"

            def get_totp(self, credential_id: str) -> str | None:
                return None

        findings = AuditService(vaults=[FlakyVault()], breach_checker=FakeBreachChecker()).run()
        # Both credentials still appear; c1 just has no issues (no password to analyze).
        assert {f.credential.host for f in findings} == {"a.com", "b.com"}

    def test_breach_check_error_does_not_crash(self) -> None:
        c = _cred("c1")
        vault = FakeVault("v", {"c1": (c, "Tnv8k!XyW2gqMpL3aZ#")})
        findings = AuditService(vaults=[vault], breach_checker=FailingBreachChecker()).run()
        # No breach issue, but the run completes.
        assert len(findings) == 1
        assert not any(i.kind == IssueKind.COMPROMISED for i in findings[0].issues)
