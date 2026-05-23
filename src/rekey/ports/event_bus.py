"""Event bus port for orchestrator events."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol

from rekey.domain.rotation import Event


class EventBus(Protocol):
    """Async pub/sub for orchestrator events.

    Multiple subscribers can listen concurrently — the web dashboard SSE
    stream is one such subscriber, the audit log writer is another.
    """

    async def publish(self, event: Event) -> None: ...

    def subscribe(self) -> AsyncIterator[Event]:
        """Return an async iterator yielding events as they arrive.

        Each call returns an independent iterator that sees events published
        after subscription.
        """
        ...
