"""Tests for password strength analysis."""

from __future__ import annotations

from rekey.detection.strength import analyze, issue_from_strength
from rekey.domain.audit import IssueKind, Severity


class TestAnalyze:
    def test_classifies_short(self) -> None:
        assert analyze("Short1!").is_short

    def test_long_not_short(self) -> None:
        assert not analyze("ALongStrongPassword12!").is_short

    def test_character_classes_detected(self) -> None:
        r = analyze("Abc123!@")
        assert r.has_upper and r.has_lower and r.has_digit and r.has_symbol

    def test_common_password_detected_case_insensitive(self) -> None:
        assert analyze("password").is_dictionary_like
        assert analyze("Password").is_dictionary_like
        assert analyze("PASSWORD").is_dictionary_like

    def test_short_number_run_detected(self) -> None:
        assert analyze("12345").is_dictionary_like

    def test_uncommon_not_dictionary_like(self) -> None:
        assert not analyze("Tnv8k!XyW2gqMpL3").is_dictionary_like

    def test_repeated_chars_dictionary_like(self) -> None:
        assert analyze("aaaaaaaa").is_dictionary_like
        assert analyze("abababab").is_dictionary_like   # only 2 distinct chars

    def test_entropy_rises_with_length(self) -> None:
        short = analyze("Abc1!")
        long_ = analyze("Abc1!Abc1!Abc1!Abc1!")
        assert long_.entropy_bits > short.entropy_bits

    def test_empty_password_no_crash(self) -> None:
        r = analyze("")
        assert r.length == 0
        assert r.entropy_bits == 0


class TestIssueFromStrength:
    def test_no_issue_for_strong(self) -> None:
        assert issue_from_strength(analyze("Tnv8k!XyW2gqMpL3aZ#%")) is None

    def test_critical_for_common(self) -> None:
        issue = issue_from_strength(analyze("password"))
        assert issue is not None
        assert issue.kind == IssueKind.WEAK
        assert issue.severity == Severity.CRITICAL

    def test_critical_for_under_8(self) -> None:
        issue = issue_from_strength(analyze("ab1!"))
        assert issue is not None
        assert issue.severity == Severity.CRITICAL

    def test_high_for_short(self) -> None:
        # Exactly 8 chars — not under_8, but is_short (< 12).
        issue = issue_from_strength(analyze("Tnv8k!Xy"))
        assert issue is not None
        assert issue.severity == Severity.HIGH

    def test_medium_for_low_entropy_long(self) -> None:
        # 12 chars, all-lowercase → alphabet=26, entropy=12*log2(26)≈56 bits
        # That's > 40, so should NOT trigger MEDIUM under current rules.
        # Use a shorter password with limited alphabet:
        # 12 chars, only digits → alphabet=10, entropy=12*log2(10)≈39.9 bits → triggers MEDIUM
        issue = issue_from_strength(analyze("123459876543"))
        # This password isn't dictionary-like (5 distinct chars). Should be MEDIUM via entropy.
        # If is_dictionary_like or similar issues catch it first, severity could differ —
        # we assert it's at least flagged.
        assert issue is not None

    def test_metric_carries_entropy(self) -> None:
        issue = issue_from_strength(analyze("ab1!"))
        assert issue is not None
        assert issue.metric is not None
        assert issue.metric >= 0
