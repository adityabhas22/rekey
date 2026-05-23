"""Audit service — composes vault readers + breach checker into a unified audit run."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence

from rekey.detection.reuse import find_reuse_groups, issues_from_reuse_groups
from rekey.detection.strength import analyze, issue_from_strength
from rekey.domain.audit import AuditFinding, Issue, IssueKind, Severity
from rekey.domain.credential import Credential
from rekey.ports.breach_check import BreachChecker
from rekey.ports.vault import VaultReader

logger = logging.getLogger(__name__)


class AuditService:
    """Run an audit across N vault readers using a breach checker.

    The actual analysis rules live in :mod:`rekey.detection`. This class only
    orchestrates: gather → analyze → build findings. Single Responsibility.
    """

    def __init__(
        self,
        *,
        vaults: Sequence[VaultReader],
        breach_checker: BreachChecker,
        compromised_threshold_critical: int = 1000,
    ) -> None:
        if not vaults:
            raise ValueError("at least one vault is required")
        self._vaults = list(vaults)
        self._breach_checker = breach_checker
        self._compromised_threshold_critical = compromised_threshold_critical

    def run(self) -> list[AuditFinding]:
        """Run the audit. Returns findings sorted by descending priority."""
        credentials, passwords = self._gather()
        per_credential = self._analyze(credentials, passwords)
        return self._build_findings(credentials, per_credential)

    # ----- internals -----

    def _gather(self) -> tuple[list[Credential], dict[str, str]]:
        credentials: list[Credential] = []
        passwords: dict[str, str] = {}
        for vault in self._vaults:
            logger.info("Listing credentials from %s", vault.name())
            for cred in vault.list_credentials():
                credentials.append(cred)
                try:
                    passwords[cred.composite_id] = vault.get_password(cred.id)
                except Exception as exc:  # noqa: BLE001  resilient per-item
                    logger.warning(
                        "Failed to read password for %s (%s); skipping",
                        cred.composite_id,
                        exc,
                    )
        return credentials, passwords

    def _analyze(
        self,
        credentials: list[Credential],
        passwords: dict[str, str],
    ) -> dict[str, list[Issue]]:
        per: dict[str, list[Issue]] = defaultdict(list)

        # Per-credential: breach + strength
        for cred in credentials:
            password = passwords.get(cred.composite_id, "")
            if not password:
                continue
            breach_issue = self._breach_issue(password)
            if breach_issue:
                per[cred.composite_id].append(breach_issue)
            strength_issue = issue_from_strength(analyze(password))
            if strength_issue:
                per[cred.composite_id].append(strength_issue)

        # Cross-credential: reuse
        reuse_pairs = [
            (cred, passwords.get(cred.composite_id, ""))
            for cred in credentials
        ]
        reuse_groups = find_reuse_groups(reuse_pairs)
        for cred_id, issues in issues_from_reuse_groups(reuse_groups).items():
            per[cred_id].extend(issues)

        return per

    def _breach_issue(self, password: str) -> Issue | None:
        try:
            count = self._breach_checker.count_breaches(password)
        except Exception as exc:  # noqa: BLE001  one HIBP failure shouldn't kill the audit
            logger.warning("Breach check failed (%s); treating as not-found", exc)
            return None
        if count <= 0:
            return None
        severity = (
            Severity.CRITICAL if count >= self._compromised_threshold_critical
            else Severity.HIGH
        )
        return Issue(
            kind=IssueKind.COMPROMISED,
            severity=severity,
            detail=f"appears in {count:,} known breaches",
            metric=count,
        )

    def _build_findings(
        self,
        credentials: list[Credential],
        per_credential: dict[str, list[Issue]],
    ) -> list[AuditFinding]:
        findings = [
            AuditFinding(
                credential=c,
                issues=tuple(per_credential.get(c.composite_id, [])),
            )
            for c in credentials
        ]
        findings.sort(key=lambda f: (-f.priority, f.credential.host))
        return findings
