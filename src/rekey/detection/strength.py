"""Password strength heuristics."""

from __future__ import annotations

import math
import string
from dataclasses import dataclass

from rekey.domain.audit import Issue, IssueKind, Severity

# Small built-in dictionary of widely-leaked common passwords. This is a
# pragmatic MVP — for stronger detection, swap in zxcvbn / dropbox-style
# dictionary attacks later.
_COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "welcome",
    "monkey", "dragon", "password1", "admin", "iloveyou", "1234567", "1234567890",
    "princess", "rockyou", "12345", "111111", "123123", "000000", "trustno1",
    "sunshine", "master", "shadow", "starwars", "passw0rd", "qwerty123",
    "football", "baseball", "superman", "batman", "ninja", "mustang", "access",
    "passw0rd!", "letmein1", "changeme", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "p@ssw0rd", "summer2024", "winter2024", "spring2024", "fall2024",
})

_SYMBOLS: frozenset[str] = frozenset(string.punctuation)


@dataclass(frozen=True, slots=True)
class StrengthReport:
    """Detailed metrics about a password."""

    length: int
    entropy_bits: float
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool
    is_short: bool                     # length < 12
    is_dictionary_like: bool           # in common list or only 1–2 distinct chars


def analyze(password: str) -> StrengthReport:
    """Compute strength metrics for a password."""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in _SYMBOLS for c in password)

    alphabet_size = 0
    if has_lower:
        alphabet_size += 26
    if has_upper:
        alphabet_size += 26
    if has_digit:
        alphabet_size += 10
    if has_symbol:
        alphabet_size += len(_SYMBOLS)
    alphabet_size = max(alphabet_size, 1)
    entropy_bits = length * math.log2(alphabet_size)

    is_dictionary_like = (
        password.lower() in _COMMON_PASSWORDS
        or (length > 0 and len(set(password)) <= 2)   # mostly repeated chars
    )

    return StrengthReport(
        length=length,
        entropy_bits=entropy_bits,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_symbol=has_symbol,
        is_short=length < 12,
        is_dictionary_like=is_dictionary_like,
    )


def issue_from_strength(report: StrengthReport) -> Issue | None:
    """Convert a strength report into an :class:`Issue`, or ``None`` if strong."""
    reasons: list[str] = []
    severity: Severity = Severity.LOW

    def bump(s: Severity) -> None:
        nonlocal severity
        if int(s) > int(severity):
            severity = s

    if report.is_dictionary_like:
        reasons.append("dictionary/common password")
        bump(Severity.CRITICAL)
    if report.length < 8:
        reasons.append(f"only {report.length} characters")
        bump(Severity.CRITICAL)
    elif report.is_short:
        reasons.append(f"only {report.length} characters")
        bump(Severity.HIGH)
    if not reasons and report.entropy_bits < 40:
        reasons.append(f"low entropy (~{report.entropy_bits:.0f} bits)")
        bump(Severity.MEDIUM)

    if not reasons:
        return None

    return Issue(
        kind=IssueKind.WEAK,
        severity=severity,
        detail=", ".join(reasons),
        metric=int(report.entropy_bits),
    )
