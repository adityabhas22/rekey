"""Tests for InMemoryEventBus."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from rekey.adapters.event_bus.in_memory import InMemoryEventBus
from rekey.domain.rotation import Event, State


def _event(attempt_id: str = "a1", state: State = State.PENDING) -> Event:
    return Event(
        attempt_id=attempt_id,
        state=state,
        timestamp=datetime.now(UTC),
        message="test",
    )


async def test_publish_delivers_to_single_subscriber() -> None:
    bus = InMemoryEventBus()
    received: list[Event] = []

    async def consumer() -> None:
        async for ev in bus.subscribe():
            received.append(ev)
            if len(received) == 2:
                return

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0.01)  # let subscribe register

    await bus.publish(_event(state=State.PENDING))
    await bus.publish(_event(state=State.FILLING_FORM))

    await asyncio.wait_for(task, timeout=1.0)
    assert [e.state for e in received] == [State.PENDING, State.FILLING_FORM]


async def test_multiple_subscribers_all_receive() -> None:
    bus = InMemoryEventBus()
    a: list[Event] = []
    b: list[Event] = []

    async def consume(into: list[Event]) -> None:
        async for ev in bus.subscribe():
            into.append(ev)
            if len(into) == 1:
                return

    task_a = asyncio.create_task(consume(a))
    task_b = asyncio.create_task(consume(b))
    await asyncio.sleep(0.01)

    await bus.publish(_event())

    await asyncio.wait_for(task_a, timeout=1.0)
    await asyncio.wait_for(task_b, timeout=1.0)
    assert len(a) == 1
    assert len(b) == 1


async def test_subscriber_unregisters_on_aclose() -> None:
    """Explicit cleanup contract: subscribers call aclose() (or get cancelled)."""
    bus = InMemoryEventBus()
    gen = bus.subscribe()

    received: list[Event] = []

    async def consumer() -> None:
        async for ev in gen:
            received.append(ev)
            if received:
                return

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0.01)
    assert bus.subscriber_count == 1

    await bus.publish(_event())
    await asyncio.wait_for(task, timeout=1.0)

    # Implicit cleanup is not guaranteed; explicit aclose() is the contract.
    await gen.aclose()
    assert bus.subscriber_count == 0


async def test_subscriber_unregisters_on_task_cancel() -> None:
    """Cancellation propagates CancelledError through the generator's finally."""
    bus = InMemoryEventBus()

    async def consumer() -> None:
        async for _ in bus.subscribe():
            pass  # consume forever

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0.01)
    assert bus.subscriber_count == 1

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    # Give the finally clause a tick to run.
    await asyncio.sleep(0.01)
    assert bus.subscriber_count == 0


async def test_publish_with_no_subscribers_is_noop() -> None:
    bus = InMemoryEventBus()
    # Should not raise or block.
    await bus.publish(_event())
    assert bus.subscriber_count == 0
