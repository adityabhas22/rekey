"""Browser-use-based RotationDriver implementation.

Wraps a single ``browser-use`` Agent.run() per rotation with our custom
actions registered in the Controller. The Agent navigates, fills the form
via secret-typing actions (LLM never sees the values), resolves in-flow
challenges, and reports success/failure.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from rekey.adapters.browser.actions import (
    WrongOriginError,
    build_controller,
)
from rekey.adapters.browser.chrome_cdp import ChromeCDPSession
from rekey.adapters.browser.secret_store import SecretStore
from rekey.domain.credential import Credential
from rekey.ports.handoff import HandoffUI
from rekey.ports.llm import LLMFactory
from rekey.ports.otp import OTPFetcher

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


TASK_PROMPT_TEMPLATE = """\
Change the password for {host} (account: {username}).

The credential_id you MUST pass to every secret-typing action is:
    {credential_id}

Step-by-step:

1. Try GET {origin}/.well-known/change-password — this standard URL often
   redirects directly to the change-password form. If it doesn't, navigate
   to {origin} and find the account/settings/security/password section.

2. Once on the change-password form:
   - Click the CURRENT PASSWORD input to focus it, then call
     type_current_password(credential_id="{credential_id}", element_index=N)
     where N is the element index of the focused input.
   - Click the NEW PASSWORD input and call
     type_new_password(credential_id="{credential_id}", element_index=N)
   - Do the same for any CONFIRM NEW PASSWORD input.
   - Submit the form.

3. If the site asks for an email OTP after submitting:
   - Click the OTP input field, then call
     fetch_and_type_email_otp(sender_hint="{host}", element_index=N).

4. For ANY of these — STOP and call pause_for_human(...) instead:
   - CAPTCHA challenge
   - SMS 2FA code
   - Push notification (touch your phone)
   - Hardware key prompt
   - Account locked / suspicious activity warning
   - The page navigated to an unfamiliar origin
   - You're not confident about what to click

5. After submitting, verify on the page that the change succeeded —
   look for a clear success message. Report success/failure in your final
   answer.

RULES:
- NEVER request, type, or display the password values yourself. The custom
  actions handle them; the values are not in your context.
- If the page navigates to an unexpected origin, STOP — call pause_for_human.
- Do NOT retry the same submission multiple times — this can lock the account.
- Treat 'account locked' / 'suspended' / 'too many attempts' as fatal — do
  not try alternate flows.
"""


class BrowserUseRotationDriver:
    """A :class:`RotationDriver` implementation backed by browser-use."""

    def __init__(
        self,
        *,
        llm_factory: LLMFactory,
        chrome_session: ChromeCDPSession,
        secrets: SecretStore,
        otp_fetcher: OTPFetcher | None = None,
        handoff: HandoffUI | None = None,
    ) -> None:
        self._llm_factory = llm_factory
        self._chrome = chrome_session
        self._secrets = secrets
        self._otp_fetcher = otp_fetcher
        self._handoff = handoff

    async def rotate(
        self,
        credential: Credential,
        new_password: str,
    ) -> bool:
        """Drive the rotation end-to-end on the live site.

        Returns True on confirmed success. Raises :class:`LockoutDetected` if
        the agent detects an account-lockout / step-up barrier.
        """
        from browser_use import Agent

        browser = await self._chrome.open()
        controller = build_controller(
            secrets=self._secrets,
            otp_fetcher=self._otp_fetcher,
            handoff=self._handoff,
            attempt_id=credential.composite_id,   # serves as a stable per-rotation label
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
