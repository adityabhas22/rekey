"""Strategy abstraction for password rotation.

Each strategy is one *approach* the state machine can try:

- :class:`InSessionStrategy` — log in with the current password (read from vault),
  then change it in settings. Requires the vault to have a working current pw.
- :class:`ForgotPasswordStrategy` — trigger the site's forgot-password flow.
  Doesn't need the current password; relies on an OTP/link delivered via a
  configured :class:`VerificationChannel`.
- :class:`ManualHandoffStrategy` — pre-arm OTP capture, open the relevant page,
  surface a "take it from here" prompt in the dashboard. User completes the
  change; rekey watches the network and verifies independently.

Strategies are *stateless and composable*. The state machine tries them in
order and verifies between attempts via an independent (fresh-context) login.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from rekey.adapters.browser.actions import WrongOriginError, build_controller
from rekey.adapters.browser.secret_store import SecretStore
from rekey.domain.credential import Credential
from rekey.ports.handoff import HandoffOutcome, HandoffUI

logger = logging.getLogger(__name__)


class StrategyOutcome(StrEnum):
    """High-level result of one strategy attempt."""

    SUBMITTED = "submitted"          # site appears to have accepted the new password
    UNRECOVERABLE = "unrecoverable"  # try the next strategy
    LOCKOUT = "lockout"              # abort — never retry
    HANDED_OFF = "handed_off"        # user took over; downstream verifier decides
    ABORTED = "aborted"              # user clicked abort


@dataclass(frozen=True, slots=True)
class StrategyResult:
    """Outcome of executing one strategy."""

    outcome: StrategyOutcome
    reason: str
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def should_verify(self) -> bool:
        """Whether the state machine should run independent verification next."""
        return self.outcome in {StrategyOutcome.SUBMITTED, StrategyOutcome.HANDED_OFF}


@dataclass
class StrategyContext:
    """Everything a strategy needs to execute.

    Built once per rotation attempt by the state machine and shared across
    strategies. The browser_session is the live CDP-attached browser.
    """

    browser_session: Any                   # browser_use.BrowserSession
    llm: Any                                # browser-use chat model instance
    secrets: SecretStore
    handoff: HandoffUI
    otp_fetcher: Any | None = None          # optional VerificationChannel
    attempt_id: str = ""
    site_label: str = ""


class RotationStrategy(Protocol):
    """One concrete approach to rotating a credential's password."""

    name: str

    async def execute(
        self,
        credential: Credential,
        new_password: str,
        ctx: StrategyContext,
    ) -> StrategyResult: ...


# --------------------------------------------------------------------- helpers


def _make_controller(ctx: StrategyContext):
    """Build a browser-use Controller with rekey's secret-typing actions."""
    return build_controller(
        secrets=ctx.secrets,
        otp_fetcher=ctx.otp_fetcher,
        handoff=ctx.handoff,
        attempt_id=ctx.attempt_id,
        site_label=ctx.site_label,
    )


async def _run_agent(task: str, ctx: StrategyContext, *, max_steps: int = 25) -> tuple[bool, str]:
    """Spin up a browser-use Agent for a focused task. Returns (success, reason)."""
    from browser_use import Agent

    controller = _make_controller(ctx)
    agent = Agent(
        task=task,
        llm=ctx.llm,
        browser=ctx.browser_session,
        controller=controller,
    )

    try:
        history = await agent.run(max_steps=max_steps)
    except WrongOriginError as e:
        return False, f"origin mismatch: {e}"
    except Exception as e:  # noqa: BLE001  surface as failure with reason
        return False, f"agent error: {type(e).__name__}: {e}"

    is_done = getattr(history, "is_done", None)
    if callable(is_done):
        try:
            done = is_done()
        except Exception:  # noqa: BLE001
            done = True
    else:
        done = history is not None

    if not done:
        return False, "agent did not complete"

    is_successful = getattr(history, "is_successful", None)
    if callable(is_successful):
        try:
            success = is_successful()
            if success is False:
                return False, "agent reported failure"
        except Exception:  # noqa: BLE001
            pass

    return True, "agent completed"


# --------------------------------------------------------------------- strategies


class InSessionStrategy:
    """Log in with the current password, then change it in settings."""

    name = "in-session"

    IN_SESSION_PROMPT = """\
Log into {host} as {username} and change the password.

The credential_id you MUST pass to every secret-typing action is:
    {credential_id}

Steps:
1. Navigate to {origin} (or look for an existing logged-in session).
2. If a login form appears:
   - Type "{username}" into the email/username field (use the normal input action).
   - Focus the password field, then call
     type_current_password(credential_id="{credential_id}", element_index=N).
   - Submit. If the site says "Incorrect password" — STOP and report failure
     IMMEDIATELY (do NOT retry the login).
3. Once logged in, navigate to account settings / security / change-password.
   Try {origin}/.well-known/change-password first.
4. On the change-password form:
   - Focus current-password (if present) → type_current_password(credential_id="{credential_id}", element_index=N).
   - Focus new-password → type_new_password(credential_id="{credential_id}", element_index=N).
   - Focus confirm-new-password (if present) → type_new_password(...).
5. Submit ONCE.
6. If the site shows a clear success message, report success.
   If it shows an error (incorrect password, password rules, generic
   "Something went wrong"), report failure with the verbatim error text.

NEVER retry a failed submit. STOP and report.

For any 2FA, CAPTCHA, push notification, or hardware-key prompt — call
pause_for_human with a precise reason and what the user needs to do.

The password values are NEVER returned to you — secret-typing actions
return "filled" only.
"""

    async def execute(
        self,
        credential: Credential,
        new_password: str,
        ctx: StrategyContext,
    ) -> StrategyResult:
        task = self.IN_SESSION_PROMPT.format(
            host=credential.host,
            origin=credential.origin,
            username=credential.username or "<unknown>",
            credential_id=credential.composite_id,
        )
        ok, reason = await _run_agent(task, ctx, max_steps=20)
        if not ok:
            return StrategyResult(
                outcome=StrategyOutcome.UNRECOVERABLE,
                reason=f"in-session: {reason}",
            )
        return StrategyResult(
            outcome=StrategyOutcome.SUBMITTED,
            reason="in-session submit appears to have succeeded",
        )


class ForgotPasswordStrategy:
    """Trigger forgot-password flow. Doesn't need the current password."""

    name = "forgot-password"

    FORGOT_PROMPT = """\
Reset the password for {host} via the forgot-password flow (no current
password is needed). Account: {username}.

The credential_id you MUST pass to every type_new_password call is:
    {credential_id}

Steps:
1. Navigate to a forgot-password page. Try (in order):
   - {origin}/forgot-password
   - {origin}/forgot
   - {origin}/account/recover
   - {origin}/login (then click "Forgot password?")
2. Enter "{username}" in the email/identifier field. Submit.
3. The site will email an OTP code or a reset link. EITHER:
   - For an OTP code: focus the code input, then call
     fetch_and_type_email_otp(sender_hint="{host}", element_index=N).
     If it returns "timeout", call pause_for_human asking the user to
     type the code manually from their email.
   - For a reset link: call pause_for_human asking the user to click
     the link in their email.
4. Once authorized, you'll see a NEW PASSWORD form.
   - Focus new-password → type_new_password(credential_id="{credential_id}", element_index=N).
   - Focus confirm-new-password (if present) → type_new_password(...).
5. Submit ONCE.
6. Report success on a clear success message; otherwise report failure
   with the verbatim error text.

NEVER retry a failed submit.

For CAPTCHA, SMS 2FA, push, or hardware-key prompts — pause_for_human.

The password values are NEVER returned to you — secret-typing actions
return "filled" only.
"""

    async def execute(
        self,
        credential: Credential,
        new_password: str,
        ctx: StrategyContext,
    ) -> StrategyResult:
        task = self.FORGOT_PROMPT.format(
            host=credential.host,
            origin=credential.origin,
            username=credential.username or "<unknown>",
            credential_id=credential.composite_id,
        )
        ok, reason = await _run_agent(task, ctx, max_steps=25)
        if not ok:
            return StrategyResult(
                outcome=StrategyOutcome.UNRECOVERABLE,
                reason=f"forgot-password: {reason}",
            )
        return StrategyResult(
            outcome=StrategyOutcome.SUBMITTED,
            reason="forgot-password submit appears to have succeeded",
        )


class ManualHandoffStrategy:
    """Pre-arm OTP capture, open the page, surface a take-it-from-here prompt."""

    name = "manual-handoff"

    OPEN_PROMPT = """\
Open the forgot-password page for {host} in a new browser tab so the
human can complete the reset manually. Account: {username}.

Steps:
1. Open a new tab and navigate to (in order, stop at the first one that
   returns a form):
   - {origin}/forgot-password
   - {origin}/forgot
   - {origin}/account/recover
2. Once the page is loaded with a visible email input, STOP and report
   success. Do NOT fill the form or submit. The human will take over.

Return success once you've opened the page. Do not interact further.
"""

    async def execute(
        self,
        credential: Credential,
        new_password: str,
        ctx: StrategyContext,
    ) -> StrategyResult:
        # First, get the page open in the user's browser.
        task = self.OPEN_PROMPT.format(
            host=credential.host,
            origin=credential.origin,
            username=credential.username or "<unknown>",
        )
        await _run_agent(task, ctx, max_steps=8)

        # Then surface a hand-off prompt with the new password.
        decision = await ctx.handoff.request_approval(
            attempt_id=ctx.attempt_id,
            site=credential.host,
            prompt=(
                f"Manual completion needed for {credential.host}. "
                "The forgot-password page is open in your browser. "
                "Complete the reset using the new password shown below, then "
                "click Approve. rekey will verify and save it to your vault."
            ),
            action_required=(
                f"New password (paste into the site): {new_password}\n\n"
                "After the site confirms the change, click APPROVE here. "
                "Click ABORT if it didn't work."
            ),
        )
        if decision.outcome == HandoffOutcome.APPROVED:
            return StrategyResult(
                outcome=StrategyOutcome.HANDED_OFF,
                reason="user approved manual completion",
            )
        if decision.outcome == HandoffOutcome.SKIPPED:
            return StrategyResult(
                outcome=StrategyOutcome.UNRECOVERABLE,
                reason="user skipped manual completion",
            )
        return StrategyResult(
            outcome=StrategyOutcome.ABORTED,
            reason="user aborted manual completion",
        )
