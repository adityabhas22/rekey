"""Tests for RotationService."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import MagicMock

import pytest

from rekey.adapters.browser.secret_store import SecretStore
from rekey.adapters.event_bus.in_memory import InMemoryEventBus
from rekey.domain.credential import Credential, VaultSource
from rekey.domain.rotation import State
from rekey.ports.rotation_driver import LockoutDetected
from rekey.services.rotation_service import RotationService


# ---- Fakes -------------------------------------------------------------


@dataclass
class FakeDriver:
    """RotationDriver test double."""

    should_succeed: bool = True
    should_raise: BaseException | None = None
    recorded_new_passwords: list[str] = field(default_factory=list)

    async def rotate(self, credential: Credential, new_password: str) -> bool:
        self.recorded_new_passwords.append(new_password)
        if self.should_raise is not None:
            raise self.should_raise
        return self.should_succeed


def _cred() -> Credential:
    return Credential(
        id="abc",
        source=VaultSource.ONEPASSWORD,
        origin="https://github.com",
        username="me@example.com",
    )


@pytest.fixture
def secrets() -> SecretStore:
    return SecretStore()


@pytest.fixture
def vault_writer() -> MagicMock:
    return MagicMock()


@pytest.fixture
def event_bus() -> InMemoryEventBus:
    return InMemoryEventBus()


def _build_service(
    *,
    driver: FakeDriver,
    secrets: SecretStore,
    vault_writer: MagicMock,
    event_bus: InMemoryEventBus,
) -> RotationService:
    return RotationService(
        driver=driver,
        vault_writer=vault_writer,
        secrets=secrets,
        event_bus=event_bus,
        password_generator=lambda _policy: "GENERATED-strong-PW-XyZ!9$",
    )


# ---- Tests -------------------------------------------------------------


class TestSuccessfulRotation:
    async def test_writes_new_password_and_marks_done(
        self,
        secrets: SecretStore,
        vault_writer: MagicMock,
        event_bus: InMemoryEventBus,
    ) -> None:
        driver = FakeDriver(should_succeed=True)
        svc = _build_service(
            driver=driver, secrets=secrets, vault_writer=vault_writer, event_bus=event_bus,
        )

        attempt = await svc.rotate(_cred(), current_password="oldpw")

        assert attempt.state == State.DONE
        assert attempt.new_password_set is True
        assert attempt.verified_login is True
        vault_writer.update_password.assert_called_once_with("abc", "GENERATED-strong-PW-XyZ!9$")
        vault_writer.append_note.assert_called_once()

    async def test_clears_secrets_after_success(
        self,
        secrets: SecretStore,
        vault_writer: MagicMock,
        event_bus: InMemoryEventBus,
    ) -> None:
        driver = FakeDriver(should_succeed=True)
        svc = _build_service(
            driver=driver, secrets=secrets, vault_writer=vault_writer, event_bus=event_bus,
        )

        await svc.rotate(_cred(), current_password="oldpw")
        assert len(secrets) == 0

    async def test_passes_generated_password_to_driver(
        self,
        secrets: SecretStore,
        vault_writer: MagicMock,
        event_bus: InMemoryEventBus,
    ) -> None:
        driver = FakeDriver(should_succeed=True)
        svc = _build_service(
            driver=driver, secrets=secrets, vault_writer=vault_writer, event_bus=event_bus,
        )
        await svc.rotate(_cred(), current_password="oldpw")
        assert driver.recorded_new_passwords == ["GENERATED-strong-PW-XyZ!9$"]


class TestDriverFailure:
    async def test_driver_returns_false_marks_failed(
        self,
        secrets: SecretStore,
        vault_writer: MagicMock,
        event_bus: InMemoryEventBus,
    ) -> None:
        driver = FakeDriver(should_succeed=False)
        svc = _build_service(
            driver=driver, secrets=secrets, vault_writer=vault_writer, event_bus=event_bus,
        )

        attempt = await svc.rotate(_cred(), current_password="oldpw")

        assert attempt.state == State.FAILED
        assert attempt.new_password_set is False
        vault_writer.update_password.assert_not_called()
        vault_writer.append_note.assert_not_called()

    async def test_driver_raises_records_failed(
        self,
        secrets: SecretStore,
        vault_writer: MagicMock,
        event_bus: InMemoryEventBus,
    ) -> None:
        driver = FakeDriver(should_raise=RuntimeError("agent died"))
        svc = _build_service(
            driver=driver, secrets=secrets, vault_writer=vault_writer, event_bus=event_bus,
        )

        attempt = await svc.rotate(_cred(), current_password="oldpw")

        assert attempt.state == State.FAILED
        assert attempt.failure_reason is not None
        assert "agent died" in attempt.failure_reason

    async def test_lockout_routes_to_lockout_state(
        self,
        secrets: SecretStore,
        vault_writer: MagicMock,
        event_bus: InMemoryEventBus,
    ) -> None:
        driver = FakeDriver(should_raise=LockoutDetected("account locked"))
        svc = _build_service(
            driver=driver, secrets=secrets, vault_writer=vault_writer, event_bus=event_bus,
        )

        attempt = await svc.rotate(_cred(), current_password="oldpw")

        assert attempt.state == State.LOCKOUT_DETECTED
        vault_writer.update_password.assert_not_called()


class TestCleanup:
    async def test_clears_secrets_even_on_failure(
        self,
        secrets: SecretStore,
        vault_writer: MagicMock,
        event_bus: InMemoryEventBus,
    ) -> None:
        driver = FakeDriver(should_raise=RuntimeError("boom"))
        svc = _build_service(
            driver=driver, secrets=secrets, vault_writer=vault_writer, event_bus=event_bus,
        )
        await svc.rotate(_cred(), current_password="oldpw")
        assert len(secrets) == 0


class TestEventsEmitted:
    async def test_publishes_events_to_bus(
        self,
        secrets: SecretStore,
        vault_writer: MagicMock,
        event_bus: InMemoryEventBus,
    ) -> None:
        import asyncio

        driver = FakeDriver(should_succeed=True)
        svc = _build_service(
            driver=driver, secrets=secrets, vault_writer=vault_writer, event_bus=event_bus,
        )

        received_states: list[State] = []
        gen = event_bus.subscribe()

        async def consume() -> None:
            async for event in gen:
                received_states.append(event.state)
                if event.state == State.DONE:
                    return

        consumer = asyncio.create_task(consume())
        await asyncio.sleep(0.01)

        await svc.rotate(_cred(), current_password="oldpw")
        await asyncio.wait_for(consumer, timeout=1.0)
        await gen.aclose()

        assert State.PENDING in received_states
        assert State.FINDING_CHANGE_PAGE in received_states
        assert State.WRITING_TO_VAULT in received_states
        assert State.DONE in received_states
