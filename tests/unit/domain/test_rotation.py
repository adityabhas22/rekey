"""Tests for RotationAttempt and state transitions."""

from __future__ import annotations

from rekey.domain.rotation import TERMINAL_STATES, RotationAttempt, State


def test_starts_pending() -> None:
    attempt = RotationAttempt(credential_id="c1")
    assert attempt.state == State.PENDING
    assert not attempt.is_terminal
    assert attempt.finished_at is None
    assert attempt.events == []
    assert attempt.attempt_id  # UUID auto-generated


def test_record_transitions_and_appends_event() -> None:
    attempt = RotationAttempt(credential_id="c1")
    event = attempt.record(State.FINDING_CHANGE_PAGE, "looking for form")
    assert attempt.state == State.FINDING_CHANGE_PAGE
    assert len(attempt.events) == 1
    assert attempt.events[0] is event
    assert event.state == State.FINDING_CHANGE_PAGE
    assert event.message == "looking for form"


def test_record_passes_data() -> None:
    attempt = RotationAttempt(credential_id="c1")
    event = attempt.record(
        State.FILLING_FORM,
        "filling",
        url="https://github.com/settings/admin",
        fields=("current", "new"),
    )
    assert event.data == {
        "url": "https://github.com/settings/admin",
        "fields": ("current", "new"),
    }


def test_terminal_state_sets_finished_at() -> None:
    attempt = RotationAttempt(credential_id="c1")
    assert attempt.finished_at is None
    attempt.record(State.DONE, "ok")
    assert attempt.finished_at is not None
    assert attempt.is_terminal
    assert attempt.duration_seconds is not None
    assert attempt.duration_seconds >= 0


def test_terminal_finished_at_not_overwritten() -> None:
    attempt = RotationAttempt(credential_id="c1")
    attempt.record(State.DONE, "ok")
    first = attempt.finished_at
    # Forcibly continue (misuse, but invariant must hold):
    attempt.record(State.FAILED, "oops")
    assert attempt.finished_at == first


def test_terminal_states_set() -> None:
    assert TERMINAL_STATES == {
        State.DONE,
        State.FAILED,
        State.SKIPPED,
        State.LOCKOUT_DETECTED,
    }


def test_each_attempt_has_unique_id() -> None:
    a = RotationAttempt(credential_id="c1")
    b = RotationAttempt(credential_id="c1")
    assert a.attempt_id != b.attempt_id


def test_explicit_attempt_id_respected() -> None:
    attempt = RotationAttempt(credential_id="c1", attempt_id="fixed-id")
    assert attempt.attempt_id == "fixed-id"
