"""Rotation state machine — the harness brain.

Replaces the agent-led v0.1 design: instead of one big LLM task prompt
running the whole rotation, we have an explicit Python state machine that:

  1. Selects a strategy (InSession → ForgotPassword → ManualHandoff).
  2. Executes it via a focused Agent.run().
  3. **Independently verifies** the change with a fresh-context login.
  4. Only writes to the vault if independent verification succeeds.
  5. On failure, tries the next strategy.

The state machine itself contains no LLM calls — it's deterministic dispatch.
LLM work happens inside strategies (focused micro-tasks) and the verifier
(small fresh-context login test).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from rekey.adapters.browser.chrome_cdp import ChromeCDPSession
from rekey.adapters.browser.secret_store import RotationSecrets, SecretStore
from rekey.domain.credential import Credential
from rekey.domain.policy import PasswordPolicy
from rekey.domain.rotation import RotationAttempt, State
from rekey.ports.event_bus import EventBus
from rekey.ports.handoff import HandoffUI
from rekey.ports.llm import LLMFactory
from rekey.ports.vault import VaultWriter
from rekey.services.password_generator import generate_password
from rekey.services.strategies import (
    ForgotPasswordStrategy,
    InSessionStrategy,
    ManualHandoffStrategy,
    RotationStrategy,
    StrategyContext,
    StrategyOutcome,
)
from rekey.services.verifier import FreshContextLoginVerifier

logger = logging.getLogger(__name__)


class RotationStateMachine:
    """Drive a credential rotation through strategies + verification.

    Construct with all the cross-cutting dependencies; call ``run(credential,
    current_password)`` to perform one rotation attempt.
    """

    def __init__(
        self,
        *,
        chrome_session: ChromeCDPSession,
        llm_factory: LLMFactory,
        secrets: SecretStore,
        event_bus: EventBus,
        vault_writer: VaultWriter,
        handoff: HandoffUI,
        otp_fetcher_factory: Any | None = None,
        strategies: Sequence[RotationStrategy] | None = None,
        cdp_url: str = "http://127.0.0.1:9222",
        password_policy: PasswordPolicy | None = None,
    ) -> None:
        self._chrome = chrome_session
        self._llm_factory = llm_factory
        self._secrets = secrets
        self._event_bus = event_bus
        self._vault_writer = vault_writer
        self._handoff = handoff
        self._otp_factory = otp_fetcher_factory
        self._cdp_url = cdp_url
        self._policy = password_policy or PasswordPolicy.strong_default()
        self._strategies: Sequence[RotationStrategy] = strategies or (
            InSessionStrategy(),
            ForgotPasswordStrategy(),
            ManualHandoffStrategy(),
        )

    async def run(
        self,
        credential: Credential,
        current_password: str,
    ) -> RotationAttempt:
        """Run the full rotation. Returns the final attempt state."""
        attempt = RotationAttempt(credential_id=credential.composite_id)
        await self._emit(attempt, State.PENDING, f"starting rotation for {credential.host}")

        new_password = generate_password(self._policy)
        self._secrets.put(
            RotationSecrets(
                credential_id=credential.composite_id,
                expected_origin=credential.origin,
                current_password=current_password,
                new_password=new_password,
            )
        )

        try:
            browser = await self._chrome.open()
            llm = self._llm_factory.make()
            otp_fetcher = self._otp_factory(browser) if self._otp_factory else None

            ctx = StrategyContext(
                browser_session=browser,
                llm=llm,
                secrets=self._secrets,
                handoff=self._handoff,
                otp_fetcher=otp_fetcher,
                attempt_id=attempt.attempt_id,
                site_label=credential.host,
            )

            for strategy in self._strategies:
                await self._emit(
                    attempt,
                    State.FINDING_CHANGE_PAGE,
                    f"trying strategy: {strategy.name}",
                    strategy=strategy.name,
                )

                result = await strategy.execute(credential, new_password, ctx)
                attempt.events[-1].data.update({"strategy_result": result.outcome.value})

                if result.outcome == StrategyOutcome.LOCKOUT:
                    attempt.failure_reason = result.reason
                    await self._emit(attempt, State.LOCKOUT_DETECTED, result.reason)
                    return attempt

                if result.outcome == StrategyOutcome.ABORTED:
                    attempt.failure_reason = "user aborted"
                    await self._emit(attempt, State.SKIPPED, result.reason)
                    return attempt

                if not result.should_verify:
                    # UNRECOVERABLE → try the next strategy
                    await self._emit(
                        attempt,
                        State.FAILED,
                        f"{strategy.name} unrecoverable: {result.reason}",
                        strategy=strategy.name,
                    )
                    continue

                # Independent verification — fresh-context login.
                await self._emit(attempt, State.VERIFYING, "verifying via fresh-context login")
                verifier = FreshContextLoginVerifier(llm=llm, cdp_url=self._cdp_url)
                verified = await verifier.verify(credential, new_password)

                if not verified:
                    await self._emit(
                        attempt,
                        State.FAILED,
                        f"{strategy.name} reported success but fresh-context login failed",
                        strategy=strategy.name,
                    )
                    continue

                # Verified — persist to vault.
                await self._write_to_vault(credential, new_password, attempt, strategy.name)
                await self._emit(attempt, State.DONE, "rotation complete and verified")
                return attempt

            # All strategies exhausted.
            attempt.failure_reason = "all strategies exhausted"
            await self._emit(attempt, State.FAILED, "all strategies exhausted")
            return attempt

        except Exception as e:  # noqa: BLE001  capture at the boundary
            attempt.failure_reason = f"{type(e).__name__}: {e}"
            await self._emit(attempt, State.FAILED, attempt.failure_reason)
            logger.exception("State machine crashed for %s", credential.composite_id)
            return attempt
        finally:
            self._secrets.clear(credential.composite_id)

    # ------------------------------------------------------------------- helpers

    async def _write_to_vault(
        self,
        credential: Credential,
        new_password: str,
        attempt: RotationAttempt,
        strategy_name: str,
    ) -> None:
        await self._emit(attempt, State.WRITING_TO_VAULT, "writing verified password to vault")
        self._vault_writer.update_password(credential.id, new_password)
        try:
            note = (
                f"Rotated by rekey on {datetime.now(UTC).isoformat()} "
                f"via strategy={strategy_name}, verified by fresh-context login."
            )
            self._vault_writer.append_note(credential.id, note)
        except Exception as e:  # noqa: BLE001  note is best-effort
            logger.warning("Could not append rotation note: %s", e)
        attempt.new_password_set = True
        attempt.verified_login = True

    async def _emit(
        self,
        attempt: RotationAttempt,
        state: State,
        message: str,
        **data: Any,
    ) -> None:
        event = attempt.record(state, message, **data)
        await self._event_bus.publish(event)
