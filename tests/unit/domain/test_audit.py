"""Tests for AuditFinding and Issue."""

from __future__ import annotations

import pytest

from rekey.domain.audit import AuditFinding, Issue, IssueKind, Severity
from rekey.domain.credential import Credential, VaultSource


@pytest.fixture
def cred() -> Credential:
    return Credential(
        id="abc",
        source=VaultSource.ONEPASSWORD,
        origin="https://github.com",
        username="me",
    )


def test_clean_finding_has_zero_priority(cred: Credential) -> None:
    f = AuditFinding(credential=cred, issues=())
    assert f.is_clean
    assert f.priority == 0
    assert f.highest_severity is None


def test_priority_sums_severities(cred: Credential) -> None:
    f = AuditFinding(
        credential=cred,
        issues=(
            Issue(IssueKind.COMPROMISED, Severity.CRITICAL, "12 breaches", metric=12),
            Issue(IssueKind.REUSED, Severity.HIGH, "used in 3 items"),
        ),
    )
    assert f.priority == int(Severity.CRITICAL) + int(Severity.HIGH)
    assert f.highest_severity == Severity.CRITICAL
    assert not f.is_clean


def test_severity_ordering() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW


def test_issue_is_frozen() -> None:
    issue = Issue(IssueKind.WEAK, Severity.LOW, "short")
    with pytest.raises((AttributeError, TypeError)):
        issue.severity = Severity.HIGH  # type: ignore[misc]


def test_finding_with_only_low_severity(cred: Credential) -> None:
    f = AuditFinding(
        credential=cred,
        issues=(Issue(IssueKind.WEAK, Severity.LOW, "11 chars"),),
    )
    assert f.priority == 1
    assert f.highest_severity == Severity.LOW
