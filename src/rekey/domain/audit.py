"""Audit findings — what's wrong with a credential."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum

from rekey.domain.credential import Credential


class IssueKind(StrEnum):
    """The category of credential hygiene problem."""

    COMPROMISED = "compromised"   # appears in known breach datasets
    REUSED = "reused"             # same password used in multiple items
    WEAK = "weak"                 # low entropy / dictionary / too short


class Severity(IntEnum):
    """Per-issue severity. Higher = more urgent.

    Stored as ``int`` so :attr:`AuditFinding.priority` can be a simple sum.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True, slots=True)
class Issue:
    """A specific finding about a credential."""

    kind: IssueKind
    severity: Severity
    detail: str                                # one-line human-readable description
    metric: int | None = None                  # e.g. breach count, reuse group size, entropy bits
    related_credential_ids: tuple[str, ...] = ()  # other items in the same reuse group


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """A credential plus everything wrong with it (possibly nothing)."""

    credential: Credential
    issues: tuple[Issue, ...]

    @property
    def priority(self) -> int:
        """Priority = sum of issue severities. 0 means clean."""
        return sum(int(i.severity) for i in self.issues)

    @property
    def is_clean(self) -> bool:
        return not self.issues

    @property
    def highest_severity(self) -> Severity | None:
        if not self.issues:
            return None
        return max(i.severity for i in self.issues)
