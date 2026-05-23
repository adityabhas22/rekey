"""Tests for reuse detection."""

from __future__ import annotations

from rekey.detection.reuse import find_reuse_groups, issues_from_reuse_groups
from rekey.domain.audit import IssueKind, Severity
from rekey.domain.credential import Credential, VaultSource


def _cred(id_: str, host: str = "site.com") -> Credential:
    return Credential(
        id=id_,
        source=VaultSource.ONEPASSWORD,
        origin=f"https://{host}",
        username="me",
    )


class TestFindReuseGroups:
    def test_no_reuse_returns_empty(self) -> None:
        groups = find_reuse_groups([
            (_cred("a"), "unique1"),
            (_cred("b", "other.com"), "unique2"),
        ])
        assert groups == []

    def test_pair_grouped(self) -> None:
        groups = find_reuse_groups([
            (_cred("a"), "samepw"),
            (_cred("b", "other.com"), "samepw"),
        ])
        assert len(groups) == 1
        assert {c.id for c in groups[0]} == {"a", "b"}

    def test_three_in_group_one_lonely(self) -> None:
        groups = find_reuse_groups([
            (_cred("a"), "pw1"),
            (_cred("b", "b.com"), "pw1"),
            (_cred("c", "c.com"), "pw1"),
            (_cred("d", "d.com"), "lonely"),
        ])
        assert len(groups) == 1
        assert {c.id for c in groups[0]} == {"a", "b", "c"}

    def test_empty_passwords_ignored(self) -> None:
        groups = find_reuse_groups([
            (_cred("a"), ""),
            (_cred("b", "b.com"), ""),
        ])
        assert groups == []

    def test_two_separate_groups(self) -> None:
        groups = find_reuse_groups([
            (_cred("a"), "pw1"),
            (_cred("b", "b.com"), "pw1"),
            (_cred("c", "c.com"), "pw2"),
            (_cred("d", "d.com"), "pw2"),
        ])
        assert len(groups) == 2
        ids = [frozenset(c.id for c in g) for g in groups]
        assert frozenset({"a", "b"}) in ids
        assert frozenset({"c", "d"}) in ids


class TestIssuesFromReuseGroups:
    def test_severity_medium_for_pair(self) -> None:
        creds = [_cred(f"id{i}", f"s{i}.com") for i in range(2)]
        issues = issues_from_reuse_groups([creds])
        flat = [i for lst in issues.values() for i in lst]
        assert flat
        assert all(i.severity == Severity.MEDIUM for i in flat)

    def test_severity_high_for_three(self) -> None:
        creds = [_cred(f"id{i}", f"s{i}.com") for i in range(3)]
        issues = issues_from_reuse_groups([creds])
        flat = [i for lst in issues.values() for i in lst]
        assert all(i.severity == Severity.HIGH for i in flat)

    def test_severity_critical_for_five(self) -> None:
        creds = [_cred(f"id{i}", f"s{i}.com") for i in range(5)]
        issues = issues_from_reuse_groups([creds])
        flat = [i for lst in issues.values() for i in lst]
        assert all(i.severity == Severity.CRITICAL for i in flat)

    def test_links_other_credential_ids(self) -> None:
        a, b, c = _cred("a"), _cred("b", "b.com"), _cred("c", "c.com")
        issues_by_id = issues_from_reuse_groups([[a, b, c]])
        assert len(issues_by_id["1password::a"]) == 1
        issue = issues_by_id["1password::a"][0]
        assert issue.kind == IssueKind.REUSED
        assert issue.metric == 3
        assert set(issue.related_credential_ids) == {"1password::b", "1password::c"}

    def test_singletons_skipped(self) -> None:
        a = _cred("a")
        assert issues_from_reuse_groups([[a]]) == {}
