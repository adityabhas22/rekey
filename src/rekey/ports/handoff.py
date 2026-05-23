"""User hand-off UI port."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class HandoffOutcome(StrEnum):
    """The user's response to a hand-off prompt."""

    APPROVED = "approved"
    ABORTED = "aborted"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class HandoffDecision:
    """Result of a hand-off prompt."""

    outcome: HandoffOutcome
    note: str | None = None


class HandoffUI(Protocol):
    """User-facing approval surface. CLI / web / desktop / push are all valid."""

    async def request_approval(
        self,
        *,
        attempt_id: str,
        site: str,
        prompt: str,
        action_required: str,
    ) -> HandoffDecision:
        """Block until the user approves, aborts, or skips this step."""
        ...

    async def announce(self, attempt_id: str, message: str) -> None:
        """Push an informational update (no decision needed)."""
        ...
