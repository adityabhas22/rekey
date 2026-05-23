"""Tests for the JSON-Lines event logger + URL-token scrubbing."""

from __future__ import annotations

import json
from pathlib import Path

from rekey.services.event_logger import JSONLinesEventLogger, scrub_text


class TestScrubText:
    def test_redacts_token_query_param(self) -> None:
        url = "https://example.com/reset?token=abc123def456ghi789jkl"
        out = scrub_text(url)
        assert "abc123def456" not in out
        assert "<redacted>" in out

    def test_redacts_code_query_param(self) -> None:
        out = scrub_text("https://x.com/v?code=12345678abcdef&keep=this")
        assert "12345678abcdef" not in out
        assert "keep=this" in out

    def test_redacts_long_path_segments(self) -> None:
        url = "https://example.com/verify/A1B2C3D4E5F6G7H8I9J0K1L2"
        out = scrub_text(url)
        assert "A1B2C3D4" not in out
        assert "/verify/" in out
        assert "<redacted>" in out

    def test_passes_through_safe_text(self) -> None:
        assert scrub_text("Normal log line about github.com") == "Normal log line about github.com"

    def test_empty(self) -> None:
        assert scrub_text("") == ""


async def test_logger_writes_and_scrubs(tmp_path: Path) -> None:
    from rekey.adapters.event_bus.in_memory import InMemoryEventBus
    from rekey.domain.rotation import RotationAttempt, State

    import asyncio

    bus = InMemoryEventBus()
    path = tmp_path / "run.jsonl"
    logger = JSONLinesEventLogger(path=path)
    logger.attach(bus)

    # Yield once so the consumer task registers its queue on the bus
    # before we publish — otherwise InMemoryEventBus snapshots an empty
    # subscriber list and drops the event.
    await asyncio.sleep(0.05)

    attempt = RotationAttempt(credential_id="c1")
    event = attempt.record(
        State.FINDING_CHANGE_PAGE,
        "Hit reset link https://example.com/reset?token=verylongsecrettoken123",
        url="https://example.com/verify/A1B2C3D4E5F6G7H8I9J0",
    )
    await bus.publish(event)

    # Give the consumer a tick to drain.
    await asyncio.sleep(0.05)

    await logger.close()

    contents = path.read_text().strip().splitlines()
    assert len(contents) == 1
    parsed = json.loads(contents[0])
    assert parsed["attempt_id"] == attempt.attempt_id
    assert parsed["state"] == "finding_change_page"
    # Message scrubbed
    assert "verylongsecrettoken123" not in parsed["message"]
    assert "<redacted>" in parsed["message"]
    # Data scrubbed too
    assert "A1B2C3D4E5F6G7H8I9J0" not in parsed["data"]["url"]
    assert "<redacted>" in parsed["data"]["url"]
