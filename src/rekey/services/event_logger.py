"""JSON-Lines event log — one line per state transition.

Subscribes to the event bus and writes a structured record per event to
``~/.rekey/runs/<attempt_id>.jsonl``. Cheap to enable, invaluable for
debugging real-world rotation runs after the fact.

Each line is a JSON object with: ``attempt_id``, ``ts`` (ISO 8601),
``state``, ``message``, ``data``. URLs that look like reset tokens
(``?token=...``, ``/setNew...?...``) are scrubbed before persisting —
those are bearer credentials we don't want lingering on disk.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import IO, Any

from rekey.domain.rotation import Event
from rekey.ports.event_bus import EventBus

logger = logging.getLogger(__name__)


# Reset tokens commonly appear as URL query params or path segments.
# Be conservative — redact anything that *looks* like a reset/verify token.
_TOKEN_QUERY_RE = re.compile(
    r"(?i)([?&](?:token|t|code|verification|verify|reset|key|otp|magic|auth|"
    r"nonce|signature|sig|jwt)=)[^&\s\"']{8,}"
)
_TOKEN_PATH_RE = re.compile(
    r"(/(?:reset|verify|confirm|magic|auth|signin|login|activate)/)"
    r"[\w\-\.~+/=]{16,}",
    re.IGNORECASE,
)


def scrub_text(value: str) -> str:
    """Redact URL tokens that look like bearer credentials."""
    if not value:
        return value
    out = _TOKEN_QUERY_RE.sub(r"\1<redacted>", value)
    out = _TOKEN_PATH_RE.sub(r"\1<redacted>", out)
    return out


def _scrub(obj: Any) -> Any:
    if isinstance(obj, str):
        return scrub_text(obj)
    if isinstance(obj, list):
        return [_scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    return obj


class JSONLinesEventLogger:
    """Async subscriber that writes events to a per-run JSONL file.

    The logger doesn't own the event bus — call ``attach(bus)`` to spawn
    a background task that consumes events and writes them. Call
    ``close()`` to stop and flush. Designed to be created once per
    rotation invocation.
    """

    def __init__(self, *, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fp: IO[str] | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    def attach(self, bus: EventBus) -> None:
        """Start the consumer task. Safe to call once."""
        if self._task is not None:
            return
        self._fp = self._path.open("a", buffering=1)  # line-buffered
        self._task = asyncio.create_task(self._consume(bus))

    async def _consume(self, bus: EventBus) -> None:
        gen = bus.subscribe()
        try:
            async for event in gen:
                if self._stop.is_set():
                    break
                self._write(event)
        finally:
            try:
                await gen.aclose()
            except Exception:  # noqa: BLE001
                pass

    def _write(self, event: Event) -> None:
        if self._fp is None:
            return
        record = {
            "attempt_id": event.attempt_id,
            "ts": event.timestamp.isoformat(),
            "state": event.state.value,
            "message": scrub_text(event.message),
            "data": _scrub(event.data),
        }
        self._fp.write(json.dumps(record, default=str) + "\n")
        self._fp.flush()

    async def close(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        if self._fp is not None:
            try:
                self._fp.close()
            except Exception:  # noqa: BLE001
                pass
            self._fp = None
