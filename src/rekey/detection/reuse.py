"""Detect credentials that share the same password."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable, Sequence

from rekey.domain.audit import Issue, IssueKind, Severity
from rekey.domain.credential import Credential


def find_reuse_groups(
    credential_passwords: Iterable[tuple[Credential, str]],
) -> list[list[Credential]]:
    """Group credentials that share the same password.

    Returns groups of 2+ credentials sharing a password. Empty/falsy passwords
    are skipped. Password values are hashed before becoming dict keys to avoid
    retaining plaintext passwords as long-lived in-memory keys.
    """
    by_hash: dict[str, list[Credential]] = defaultdict(list)
    for cred, password in credential_passwords:
        if not password:
            continue
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        by_hash[digest].append(cred)
    return [group for group in by_hash.values() if len(group) > 1]


def issues_from_reuse_groups(
    groups: Iterable[Sequence[Credential]],
) -> dict[str, list[Issue]]:
    """Convert reuse groups into per-credential :class:`Issue` records.

    Keyed by :attr:`Credential.composite_id` so callers can attach issues
    across multiple vault sources without collisions.
    """
    issues_by_credential_id: dict[str, list[Issue]] = defaultdict(list)
    for group in groups:
        n = len(group)
        if n < 2:
            continue
        severity = (
            Severity.CRITICAL if n >= 5
            else Severity.HIGH if n >= 3
            else Severity.MEDIUM
        )
        group_ids = tuple(c.composite_id for c in group)
        for c in group:
            others = tuple(cid for cid in group_ids if cid != c.composite_id)
            issues_by_credential_id[c.composite_id].append(
                Issue(
                    kind=IssueKind.REUSED,
                    severity=severity,
                    detail=f"password reused across {n} items",
                    metric=n,
                    related_credential_ids=others,
                )
            )
    return dict(issues_by_credential_id)
