"""In-memory async pub/sub event bus."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from rekey.domain.rotation import Event


class InMemoryEventBus:
    """Async fan-out pub/sub.

    Implements :class:`rekey.ports.EventBus`.

    Each subscriber gets an independent unbounded queue. Slow subscribers
    don't block publishers — but their queue can grow without bound, so
    subscribers should consume promptly or be cancelled.

    Cleanup contract: subscribers must close the generator (via ``aclose()``,
    ``contextlib.aclosing``, or by cancelling the iterating task) for the
    bus to unregister them. Cancellation by FastAPI on SSE-client disconnect
    triggers this automatically; explicit ``break``/``return`` does not.
    """

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[Event]] = []
        self._lock = asyncio.Lock()

    async def publish(self, event: Event) -> None:
        async with self._lock:
            targets = list(self._subscribers)
        for queue in targets:
            await queue.put(event)

    async def subscribe(self) -> AsyncIterator[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue()
        async with self._lock:
            self._subscribers.append(queue)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            async with self._lock:
                if queue in self._subscribers:
                    self._subscribers.remove(queue)

    @property
    def subscriber_count(self) -> int:
        """Number of active subscribers (testing/debug only)."""
        return len(self._subscribers)
