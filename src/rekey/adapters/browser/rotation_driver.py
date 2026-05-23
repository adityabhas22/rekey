"""Browser-use-based RotationDriver implementation.

Wraps a single ``browser-use`` Agent.run() per rotation with our custom
actions registered in the Controller. The Agent navigates, fills the form
via secret-typing actions (LLM never sees the values), resolves in-flow
challenges, and reports success/failure.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from rekey.adapters.browser.actions import (
    WrongOriginError,
    build_controller,
)
from rekey.adapters.browser.chrome_cdp import ChromeCDPSession
from rekey.adapters.browser.secret_store import SecretStore
from rekey.domain.credential import Credential
from rekey.ports.handoff import HandoffUI
from rekey.ports.llm import LLMFactory

if TYPE_CHECKING:
    from rekey.ports.otp import OTPFetcher  # noqa: F401  used in OTPFetcherFactory alias

logger = logging.getLogger(__name__)


TASK_PROMPT_TEMPLATE = """\
Change the password for {host} (account: {username}).

The credential_id you MUST pass to every secret-typing action is:
    {credential_id}

The credential currently stored in the vault may or may not have the correct
CURRENT password. Use this decision tree.

═══ PATH A — In-session change (try this first) ═══

A1. Try GET {origin}/.well-known/change-password — this often redirects
    directly to the change-password form.
A2. If that fails or you land on a login page, navigate to {origin} and
    find the account/settings/security/password section.

A3. If you reach a LOGIN form (the site requires you to log in first):
    - Type the email "{username}" into the email/username field using
      the standard `input` action.
    - Focus the password field, then call
      type_current_password(credential_id="{credential_id}", element_index=N).
    - Submit.
    - If the site says "Incorrect password" / "Wrong password" / similar:
      ↓ ABANDON PATH A. Switch to PATH B (forgot-password).

A4. If you reach the CHANGE-PASSWORD form (you are logged in):
    - Focus the CURRENT password field → type_current_password(...).
    - Focus the NEW password field → type_new_password(...).
    - Focus any CONFIRM NEW PASSWORD field → type_new_password(...) again.
    - Submit.
    - If the site says "Incorrect current password" / similar:
      ↓ ABANDON PATH A. Switch to PATH B.

═══ PATH B — Forgot-password flow ═══

Use this whenever PATH A is blocked (wrong current password, no in-session
change form, or login keeps failing).

B1. Find and navigate to a "Forgot password?" / "Reset password" link.
    - Often at {origin}/forgot, {origin}/forgot-password, or via the
      login page's "Forgot password?" link.
B2. Enter the email "{username}" in the reset form. Submit.
B3. The site will email a verification code OR a reset link.
    - For an OTP code: focus the code input on the page, then call
      fetch_and_type_email_otp(sender_hint="{host}", element_index=N).
      This opens Gmail, finds the code, and types it for you.
      If it returns "timeout", call pause_for_human asking the user to
      type the code manually.
    - For a reset link only (no inline code): call pause_for_human
      asking the user to click the link in their email.
B4. Once authorized, you'll see a NEW-PASSWORD form.
    - Focus the new-password field → type_new_password(credential_id=...).
    - Focus the confirm field (if any) → type_new_password(...).
    - Submit.

═══ FOR ANY OF THESE — STOP and call pause_for_human ═══

- CAPTCHA challenge
- SMS 2FA code (not email — SMS goes to phone, only the human can type it)
- Push notification (touch your phone)
- Hardware key prompt
- Account locked / suspicious activity warning / "too many attempts"
- The page navigated to an unfamiliar origin (not {host} or a Google OAuth subdomain)
- You're not confident about what to click

═══ RULES — read carefully ═══

- NEVER request, type, or display the password values yourself. The
  custom actions handle them; the values are not in your context.
- If the page navigates to an unexpected origin, STOP — call pause_for_human.
- Do NOT retry the same submission multiple times — that can lock the account.
- Treat 'account locked' / 'suspended' / 'too many attempts' as fatal — STOP.
- After submitting, verify on the page that the change succeeded.
  Look for a clear success message. Report success or failure in your
  final answer.
"""


OTPFetcherFactory = Callable[[Any], "OTPFetcher | None"]


class BrowserUseRotationDriver:
    """A :class:`RotationDriver` implementation backed by browser-use.

    ``otp_fetcher_factory`` (optional) is a callable that takes the live
    ``browser_session`` and returns an OTPFetcher — used so e.g. the
    Webmail-tab fetcher can share the agent's browser session for tab
    management. If ``None``, OTP automation is disabled and the LLM will
    fall back to ``pause_for_human`` for email codes.
    """

    def __init__(
        self,
        *,
        llm_factory: LLMFactory,
        chrome_session: ChromeCDPSession,
        secrets: SecretStore,
        otp_fetcher_factory: OTPFetcherFactory | None = None,
        handoff: HandoffUI | None = None,
    ) -> None:
        self._llm_factory = llm_factory
        self._chrome = chrome_session
        self._secrets = secrets
        self._otp_fetcher_factory = otp_fetcher_factory
        self._handoff = handoff

    async def rotate(
        self,
        credential: Credential,
        new_password: str,   # noqa: ARG002  staged in SecretStore by service; driver reads via actions
    ) -> bool:
        """Drive the rotation end-to-end on the live site.

        Returns True on confirmed success. The ``new_password`` argument is
        kept for the port contract; the driver reads it indirectly via the
        :class:`SecretStore` (populated by :class:`RotationService` before
        calling here).
        """
        from browser_use import Agent

        browser = await self._chrome.open()
        otp_fetcher = self._otp_fetcher_factory(browser) if self._otp_fetcher_factory else None

        controller = build_controller(
            secrets=self._secrets,
            otp_fetcher=otp_fetcher,
            handoff=self._handoff,
            attempt_id=credential.composite_id,   # stable per-rotation label
            site_label=credential.host,
        )
        llm = self._llm_factory.make()

        task = TASK_PROMPT_TEMPLATE.format(
            host=credential.host,
            username=credential.username or "<unknown>",
            credential_id=credential.composite_id,
            origin=credential.origin,
        )

        agent = Agent(
            task=task,
            llm=llm,
            browser=browser,
            controller=controller,
        )

        try:
            history = await agent.run()
        except WrongOriginError as e:
            logger.warning("Refused to type secret due to origin mismatch: %s", e)
            return False

        return self._is_successful(history)

    @staticmethod
    def _is_successful(history: object) -> bool:
        """Best-effort interpretation of browser-use's AgentHistoryList outcome."""
        for method_name in ("is_successful", "is_done"):
            method = getattr(history, method_name, None)
            if callable(method):
                try:
                    result = method()
                    if isinstance(result, bool):
                        return result
                except Exception:  # noqa: BLE001  best-effort introspection
                    pass
        # Fallback: assume success only if we got back any history at all.
        return history is not None
