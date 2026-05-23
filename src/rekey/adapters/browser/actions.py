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


async def _type_secret_into_element(
    *,
    browser_session,    # noqa: ANN001  browser-use BrowserSession (avoid string forward ref)
    element_index: int,
    value: str,
    sensitive_label: str,
) -> str:
    """Type ``value`` into the element at ``element_index`` via browser-use's
    ``TypeTextEvent``, which dispatches real keystrokes via CDP.

    ``is_sensitive=True`` + ``sensitive_key_name`` make browser-use log the
    typed value as ``<label>`` rather than the actual content.
    """
    from browser_use.browser.events import TypeTextEvent

    node = await browser_session.get_element_by_index(element_index)
    if node is None:
        return f"no element at index {element_index}"
    event = browser_session.event_bus.dispatch(
        TypeTextEvent(
            node=node,
            text=value,
            clear=True,
            is_sensitive=True,
            sensitive_key_name=sensitive_label,
        )
    )
    await event
    return "filled"


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
        browser_session,   # noqa: ANN001 — auto-injected by browser-use; no annotation
    ) -> str:
        rec = secrets.get(credential_id)
        await verify_origin(browser_session, rec.expected_origin)
        return await _type_secret_into_element(
            browser_session=browser_session,
            element_index=element_index,
            value=rec.current_password,
            sensitive_label="<current_password>",
        )

    @controller.action(
        "Type the newly-generated NEW password into the element at the given "
        "index. Use for 'new password' and 'confirm new password' fields. "
        "The password value is NEVER returned to you — only 'filled'."
    )
    async def type_new_password(
        credential_id: str,
        element_index: int,
        browser_session,   # noqa: ANN001
    ) -> str:
        rec = secrets.get(credential_id)
        await verify_origin(browser_session, rec.expected_origin)
        return await _type_secret_into_element(
            browser_session=browser_session,
            element_index=element_index,
            value=rec.new_password,
            sensitive_label="<new_password>",
        )

    if otp_fetcher is not None:
        @controller.action(
            "Wait for an email containing a verification/reset code matching "
            "a sender hint, then type the code into the element at the given "
            "index. Returns 'filled' on success or 'timeout' if no email arrived."
        )
        async def fetch_and_type_email_otp(
            sender_hint: str,
            element_index: int,
            browser_session,   # noqa: ANN001
            window_seconds: int = 120,
        ) -> str:
            code = await otp_fetcher.fetch_code(
                sender_hint=sender_hint or None,
                window_seconds=window_seconds,
            )
            if code is None:
                return "timeout"
            return await _type_secret_into_element(
                browser_session=browser_session,
                element_index=element_index,
                value=code,
                sensitive_label="<otp_code>",
            )

        @controller.action(
            "Wait for a password-reset email containing a clickable link, "
            "extract the link, and navigate the current tab to it. Use this "
            "when the site shows 'check your email for a link' rather than "
            "asking for an OTP code on-page. Returns 'navigated' on success "
            "or 'timeout' if no email arrived in window_seconds."
        )
        async def fetch_and_open_reset_link(
            sender_hint: str,
            browser_session,   # noqa: ANN001
            window_seconds: int = 180,
        ) -> str:
            fetch_link = getattr(otp_fetcher, "fetch_link", None)
            if not callable(fetch_link):
                return "no_link_channel"
            link = await fetch_link(
                sender_hint=sender_hint or None,
                window_seconds=window_seconds,
            )
            if link is None:
                return "timeout"
            # Navigate the current tab to the link.
            page = await browser_session.get_current_page()
            if page is None:
                return "no_active_page"
            try:
                await page.navigate(link)
            except Exception as e:  # noqa: BLE001  surface as failure string
                return f"navigation_failed: {type(e).__name__}"
            logger.info("Navigated to reset link from email (length=%d)", len(link))
            return "navigated"

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
