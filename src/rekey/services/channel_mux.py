"""Verification-channel multiplexer.

When the agent needs an OTP, it doesn't know whether it'll arrive by SMS,
by Mail.app rule, by webmail, or via TOTP. The mux fires *all* configured
channels concurrently and returns the first code that arrives — cancelling
the rest. This is also how we get the right answer when a site sends OTPs
via *both* email and SMS (we win on whichever fires first).

Priority is implicit: faster channels (TOTP, chat.db, Mail.app rule push)
will normally beat polling channels (webmail-tab scrape).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class VerificationChannelMux:
    """Race configured channels to fetch the first matching OTP / link."""

    def __init__(
        self,
        *,
        chat_db: Any = None,            # ChatDbReader
        mail_rule: Any = None,          # MailRuleReceiver
        webmail_tab: Any = None,        # WebmailTabOTPFetcher
        totp: Any = None,               # CLITOTPChannel
    ) -> None:
        self._chat_db = chat_db
        self._mail_rule = mail_rule
        self._webmail_tab = webmail_tab
        self._totp = totp

    def has_any(self) -> bool:
        return any((self._chat_db, self._mail_rule, self._webmail_tab))

    async def fetch_code(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 120,
        digits: tuple[int, int] = (4, 8),
    ) -> str | None:
        """Race all configured email/SMS channels; first match wins."""
        tasks: list[asyncio.Task[str | None]] = []
        names: list[str] = []

        if self._chat_db is not None and self._chat_db.available():
            tasks.append(
                asyncio.create_task(
                    self._chat_db.wait_for_code(
                        sender_hint=sender_hint,
                        window_seconds=window_seconds,
                        digits=digits,
                    )
                )
            )
            names.append("chat_db")

        if self._mail_rule is not None:
            tasks.append(
                asyncio.create_task(
                    self._mail_rule.wait_for_code(
                        sender_hint=sender_hint,
                        window_seconds=window_seconds,
                        digits=digits,
                    )
                )
            )
            names.append("mail_rule")

        if self._webmail_tab is not None:
            tasks.append(
                asyncio.create_task(
                    self._webmail_tab.fetch_code(
                        sender_hint=sender_hint,
                        window_seconds=window_seconds,
                        digits=digits,
                    )
                )
            )
            names.append("webmail_tab")

        return await self._race(tasks, names, label="OTP code")

    async def fetch_link(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 180,
    ) -> str | None:
        """Race all configured channels for a reset link."""
        tasks: list[asyncio.Task[str | None]] = []
        names: list[str] = []

        if self._chat_db is not None and self._chat_db.available():
            tasks.append(
                asyncio.create_task(
                    self._chat_db.wait_for_link(
                        sender_hint=sender_hint,
                        window_seconds=window_seconds,
                    )
                )
            )
            names.append("chat_db")

        if self._mail_rule is not None:
            tasks.append(
                asyncio.create_task(
                    self._mail_rule.wait_for_link(
                        sender_hint=sender_hint,
                        window_seconds=window_seconds,
                    )
                )
            )
            names.append("mail_rule")

        if self._webmail_tab is not None:
            tasks.append(
                asyncio.create_task(
                    self._webmail_tab.fetch_link(
                        sender_hint=sender_hint,
                        window_seconds=window_seconds,
                    )
                )
            )
            names.append("webmail_tab")

        return await self._race(tasks, names, label="reset link")

    async def _race(
        self,
        tasks: list[asyncio.Task[str | None]],
        names: list[str],
        *,
        label: str,
    ) -> str | None:
        if not tasks:
            logger.info("Mux: no channels configured for %s", label)
            return None
        try:
            pending: set[asyncio.Task[str | None]] = set(tasks)
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    if t.cancelled():
                        continue
                    try:
                        result = t.result()
                    except Exception as e:  # noqa: BLE001
                        logger.debug("Mux task error: %s", e)
                        continue
                    if result:
                        idx = tasks.index(t)
                        logger.info("Mux: %s from %s", label, names[idx])
                        return result
            return None
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            # Drain cancellations
            await asyncio.gather(*tasks, return_exceptions=True)
