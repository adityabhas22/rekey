"""Webmail-tab OTP fetcher — reads OTP codes / reset links from an open Gmail tab.

Requires the user to be logged into Gmail in the same browser process that
the rotation agent is attached to (over CDP). Opens a new tab, performs a
Gmail search filtered by sender + recency, polls until a matching email
appears, extracts the code or link, and closes the tab.

Falls back gracefully (returns ``None``) if Gmail isn't reachable or the
expected email never arrives within ``window_seconds`` — the agent will
then escalate to ``pause_for_human``.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import quote

logger = logging.getLogger(__name__)


# Match plausible OTP codes — 4-8 contiguous digits, possibly bracketed
# by non-digits. Word boundaries prevent matching parts of longer numbers.
_OTP_RE = re.compile(r"(?<!\d)(\d{4,8})(?!\d)")

# Match likely reset/verify links. Permissive: we only require the URL to
# contain one of the trigger words.
_RESET_LINK_RE = re.compile(
    r"https?://[^\s<>\"']+(?:reset|verify|confirm|password|change)[^\s<>\"']*",
    re.IGNORECASE,
)


GMAIL_SEARCH_URL = "https://mail.google.com/mail/u/0/#search/{query}"


class WebmailTabOTPFetcher:
    """Reads OTPs from Gmail by navigating in a new tab inside the same browser.

    Implements :class:`rekey.ports.OTPFetcher`.

    Construct with the live ``browser_session`` the agent is using so that
    tab management is unified.
    """

    def __init__(
        self,
        browser_session: Any,
        *,
        poll_interval: float = 2.0,
        initial_render_delay: float = 2.5,
    ) -> None:
        self._browser_session = browser_session
        self._poll_interval = poll_interval
        self._initial_render_delay = initial_render_delay

    async def fetch_code(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 120,
        digits: tuple[int, int] = (4, 8),
    ) -> str | None:
        """Open Gmail, find recent email from ``sender_hint``, extract numeric code."""

        def _match(text: str) -> str | None:
            for m in _OTP_RE.finditer(text):
                value = m.group(1)
                if digits[0] <= len(value) <= digits[1]:
                    return value
            return None

        return await self._poll_gmail(sender_hint, window_seconds, _match, "code")

    async def fetch_link(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 180,
    ) -> str | None:
        """Open Gmail, find recent email from ``sender_hint``, extract reset link."""

        def _match(text: str) -> str | None:
            m = _RESET_LINK_RE.search(text)
            return m.group(0) if m else None

        return await self._poll_gmail(sender_hint, window_seconds, _match, "link")

    # ---- internals ----

    async def _poll_gmail(
        self,
        sender_hint: str | None,
        window_seconds: int,
        matcher,
        label: str,
    ) -> str | None:
        url = self._search_url(sender_hint)
        logger.info("OTPFetcher opening Gmail search: %s", url)

        page = await self._open_search_page(url)
        if page is None:
            logger.warning("OTPFetcher: could not open Gmail tab")
            return None

        try:
            await asyncio.sleep(self._initial_render_delay)
            deadline = time.monotonic() + window_seconds
            while time.monotonic() < deadline:
                text = await self._extract_visible_text(page)
                if text:
                    match = matcher(text)
                    if match:
                        logger.info("OTPFetcher matched %s from Gmail", label)
                        return match
                # Refresh the inbox if we haven't matched yet — new emails
                # may have arrived. (Light-weight: most apps fan in <30s.)
                await asyncio.sleep(self._poll_interval)
                try:
                    await page.evaluate("location.reload()")
                except Exception as e:  # noqa: BLE001  best-effort reload
                    logger.debug("Reload failed: %s", e)
            logger.warning("OTPFetcher timeout after %ds (no %s)", window_seconds, label)
            return None
        finally:
            await self._close_page(page)

    def _search_url(self, sender_hint: str | None) -> str:
        parts = ["newer_than:1h", "in:inbox"]
        if sender_hint:
            parts.append(f"from:{sender_hint}")
        return GMAIL_SEARCH_URL.format(query=quote(" ".join(parts)))

    async def _open_search_page(self, url: str) -> Any | None:
        try:
            page = await self._browser_session.new_page()
        except Exception as e:  # noqa: BLE001  surface as None / log
            logger.warning("OTPFetcher: new_page failed: %s", e)
            return None
        try:
            await page.navigate(url)
        except Exception as e:  # noqa: BLE001
            logger.warning("OTPFetcher: navigate to Gmail failed: %s", e)
            await self._close_page(page)
            return None
        return page

    async def _extract_visible_text(self, page: Any) -> str:
        try:
            text = await page.evaluate("document.body.innerText || ''")
            return text if isinstance(text, str) else str(text or "")
        except Exception as e:  # noqa: BLE001  fall back to empty
            logger.debug("OTPFetcher: extract_visible_text failed: %s", e)
            return ""

    async def _close_page(self, page: Any) -> None:
        try:
            await self._browser_session.close_page(page)
        except Exception as e:  # noqa: BLE001  detach is best-effort
            logger.debug("OTPFetcher: close_page failed: %s", e)
