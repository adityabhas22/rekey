"""Rotation state machine types."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4


class State(StrEnum):
    """States in the rotation flow.

    The state machine is linear with explicit failure transitions::

        PENDING
          → FINDING_CHANGE_PAGE
          → FILLING_FORM
          → AWAITING_HUMAN_APPROVAL
          → SUBMITTING
          → HANDLING_CHALLENGES
          → VERIFYING
          → WRITING_TO_VAULT
          → DONE

        Any non-terminal → FAILED              (recoverable; safe to skip and continue)
        Any non-terminal → LOCKOUT_DETECTED    (abort; do not retry)
        User can SKIP any non-terminal state.
    """

    PENDING = "pending"
    FINDING_CHANGE_PAGE = "finding_change_page"
    FILLING_FORM = "filling_form"
    AWAITING_HUMAN_APPROVAL = "awaiting_human_approval"
    SUBMITTING = "submitting"
    HANDLING_CHALLENGES = "handling_challenges"
    VERIFYING = "verifying"
    WRITING_TO_VAULT = "writing_to_vault"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    LOCKOUT_DETECTED = "lockout_detected"


TERMINAL_STATES: frozenset[State] = frozenset({
    State.DONE,
    State.FAILED,
    State.SKIPPED,
    State.LOCKOUT_DETECTED,
})


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class Event:
    """An immutable record of a state transition or notable occurrence."""

    attempt_id: str
    state: State
    timestamp: datetime
    message: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RotationAttempt:
    """The live record of one credential rotation.

    Mutable by design: the state machine transitions it. Use :meth:`record`
    to transition — it appends an event and updates the state atomically.
    """

    credential_id: str
    attempt_id: str = field(default_factory=lambda: str(uuid4()))
    state: State = State.PENDING
    started_at: datetime = field(default_factory=_utcnow)
    finished_at: datetime | None = None
    events: list[Event] = field(default_factory=list)
    failure_reason: str | None = None
    new_password_set: bool = False
    verified_login: bool = False

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def record(self, state: State, message: str, **data: Any) -> Event:
        """Transition to ``state`` and append an event.

        Returns the event for callers that want to publish it onto a bus.
        Setting ``finished_at`` happens only the first time the attempt enters
        a terminal state — subsequent records do not overwrite it.
        """
        event = Event(
            attempt_id=self.attempt_id,
            state=state,
            timestamp=_utcnow(),
            message=message,
            data=data,
        )
        self.state = state
        self.events.append(event)
        if state in TERMINAL_STATES and self.finished_at is None:
            self.finished_at = event.timestamp
        return event
