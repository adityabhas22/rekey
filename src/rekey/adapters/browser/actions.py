"""Custom browser-use actions — *the security boundary*.

The LLM driving the browser never sees password or OTP values in its
context. Each action reads secrets from a per-rotation :class:`SecretStore`
and types them via the browser-use Element API directly.

The action functions only return short status strings (``"filled"``,
``"timeout"``, …) — secret values are never in their return values.

Origin is validated before typing: if the page navigated to a different
origin than the credential's, the action refuses.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from rekey.adapters.browser.secret_store import SecretStore
from rekey.domain.credential import canonical_origin
from rekey.ports.handoff import HandoffUI
from rekey.ports.otp import OTPFetcher

if TYPE_CHECKING:
    from browser_use import BrowserSession, Controller

logger = logging.getLogger(__name__)


class WrongOriginError(Exception):
    """Refused to type a secret because the page is not on the expected origin."""


async def verify_origin(browser_session: "BrowserSession", expected: str) -> None:
    """Raise :class:`WrongOriginError` if the current page isn't on ``expected``."""
    current_url = await browser_session.get_current_page_url()
    if not current_url:
        raise WrongOriginError("could not determine current page URL")
    current = canonical_origin(current_url)
    if current != expected:
        raise WrongOriginError(
            f"refusing to type secret: page is at {current}, expected {expected}"
        )


def build_controller(
    *,
    secrets: SecretStore,
    otp_fetcher: OTPFetcher | None = None,
    handoff: HandoffUI | None = None,
    attempt_id: str = "",
    site_label: str = "",
) -> "Controller":
    """Build a browser-use Controller with rekey's custom actions registered.

    Returns a fresh Controller per call; callers should build one per
    rotation since ``attempt_id`` and ``site_label`` are captured in closures.
    """
    from browser_use import Controller

    controller = Controller()

    @controller.action(
        "Type the credential's CURRENT password into the element at the given "
        "index. credential_id MUST match the one in the task description. "
        "Use on a password input (autocomplete='current-password'). The "
        "password value is NEVER returned to you — only 'filled'."
    )
    async def type_current_password(
        credential_id: str,
        element_index: int,
        browser_session: "BrowserSession",
    ) -> str:
        rec = secrets.get(credential_id)
        await verify_origin(browser_session, rec.expected_origin)
        element = await browser_session.get_element_by_index(element_index)
        if element is None:
            return f"no element at index {element_index}"
        await element.fill(rec.current_password)
        logger.info("Filled current password for %s", credential_id)
        return "filled"

    @controller.action(
        "Type the newly-generated NEW password into the element at the given "
        "index. Use for 'new password' and 'confirm new password' fields. "
        "The password value is NEVER returned to you — only 'filled'."
    )
    async def type_new_password(
        credential_id: str,
        element_index: int,
        browser_session: "BrowserSession",
    ) -> str:
        rec = secrets.get(credential_id)
        await verify_origin(browser_session, rec.expected_origin)
        element = await browser_session.get_element_by_index(element_index)
        if element is None:
            return f"no element at index {element_index}"
        await element.fill(rec.new_password)
        logger.info("Filled new password for %s", credential_id)
        return "filled"

    if otp_fetcher is not None:
        @controller.action(
            "Wait for an email containing a verification/reset code matching "
            "a sender hint, then type the code into the element at the given "
            "index. Returns 'filled' on success or 'timeout' if no email arrived."
        )
        async def fetch_and_type_email_otp(
            sender_hint: str,
            element_index: int,
            browser_session: "BrowserSession",
            window_seconds: int = 120,
        ) -> str:
            code = await otp_fetcher.fetch_code(
                sender_hint=sender_hint or None,
                window_seconds=window_seconds,
            )
            if code is None:
                return "timeout"
            element = await browser_session.get_element_by_index(element_index)
            if element is None:
                return f"no element at index {element_index}"
            await element.fill(code)
            return "filled"

    if handoff is not None:
        @controller.action(
            "Pause and ask the human user. Use for CAPTCHAs, SMS 2FA, push 2FA "
            "(touch your phone), hardware key prompts, or anything ambiguous. "
            "Returns 'approved', 'aborted', or 'skipped'."
        )
        async def pause_for_human(reason: str, what_to_do: str) -> str:
            decision = await handoff.request_approval(
                attempt_id=attempt_id,
                site=site_label,
                prompt=reason,
                action_required=what_to_do,
            )
            return decision.outcome.value

    return controller
