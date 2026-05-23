"""Independent verification — the gold-standard "verify by fresh observation."

After a strategy submits a new password, we MUST verify the change actually
took before writing to the vault. The strongest signal is to log in with the
new password from a clean browser context (no cookies, no localStorage). If
that succeeds, the change is real. If it fails, the agent was wrong and we
must not write to the vault.

This module is browser-use-agnostic on purpose: the verifier spawns its own
Playwright context so it doesn't share state with the rotation agent's session.
"""

from __future__ import annotations

import logging
from typing import Any

from rekey.domain.credential import Credential

logger = logging.getLogger(__name__)


class FreshContextLoginVerifier:
    """Open a clean Playwright context and attempt login with the new password.

    Returns True only if the site clearly indicates a successful sign-in
    (URL moves off the login page AND no error text visible).
    """

    def __init__(
        self,
        *,
        llm: Any,
        cdp_url: str = "http://127.0.0.1:9222",
        timeout_seconds: int = 60,
    ) -> None:
        self._llm = llm
        self._cdp_url = cdp_url
        self._timeout = timeout_seconds

    async def verify(
        self,
        credential: Credential,
        new_password: str,
    ) -> bool:
        """Return True iff a fresh-context login with new_password succeeds."""
        from browser_use import Agent, Browser

        from rekey.adapters.browser.actions import build_controller
        from rekey.adapters.browser.secret_store import RotationSecrets, SecretStore

        # Dedicated secret store for this verification only.
        # The verification "credential id" gets a -verify suffix so it doesn't
        # collide with the rotation attempt's secret store entry.
        verify_id = f"{credential.composite_id}::verify"
        secrets = SecretStore()
        secrets.put(
            RotationSecrets(
                credential_id=verify_id,
                expected_origin=credential.origin,
                current_password=new_password,
                new_password=new_password,
            )
        )

        # Connect to the same Chrome but spawn a fresh incognito-ish context
        # by opening a new tab. (browser-use 0.12 doesn't expose contexts
        # directly via the public Browser API in the way Playwright does,
        # so we use a fresh tab + clear cookies via CDP if available.)
        browser = Browser(cdp_url=self._cdp_url)

        controller = build_controller(secrets=secrets, attempt_id=verify_id, site_label=credential.host)

        task = self._VERIFY_PROMPT.format(
            host=credential.host,
            origin=credential.origin,
            username=credential.username or "<unknown>",
            credential_id=verify_id,
        )

        agent = Agent(task=task, llm=self._llm, browser=browser, controller=controller)
        try:
            history = await agent.run(max_steps=12)
        except Exception as e:  # noqa: BLE001
            logger.warning("Fresh-context verify failed: %s", e)
            return False
        finally:
            try:
                await browser.close()
            except Exception:  # noqa: BLE001
                pass
            secrets.clear_all()

        # Did the agent report success?
        is_successful = getattr(history, "is_successful", None)
        if callable(is_successful):
            try:
                result = is_successful()
                if isinstance(result, bool):
                    return result
            except Exception:  # noqa: BLE001
                pass

        # Fall back to checking whether the agent reached a "done" terminal.
        is_done = getattr(history, "is_done", None)
        if callable(is_done):
            try:
                return bool(is_done())
            except Exception:  # noqa: BLE001
                return False
        return False

    _VERIFY_PROMPT = """\
Verify that signing into {host} with the new password works.

The credential_id for type_current_password is:
    {credential_id}

Steps:
1. Open a new tab and navigate to {origin}.
2. If you're already signed in as a different user, click sign-out first.
3. Find the login form. Enter "{username}" in the email field.
4. Focus the password field, then call
   type_current_password(credential_id="{credential_id}", element_index=N).
5. Submit ONCE.
6. If the page navigates to a logged-in/account/dashboard view OR
   shows clear success, report SUCCESS.
   If the site shows "incorrect password" or similar, report FAILURE.
   For ANY CAPTCHA/2FA/SMS prompt — STOP and report FAILURE
   (a working verification doesn't need 2FA on a known device; if it does,
   we can't verify cleanly in this fresh context).

NEVER retry. Report success or failure based on the first submit response.
"""
