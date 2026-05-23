"""Tests for WebmailTabOTPFetcher."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from rekey.adapters.mail.webmail_tab import WebmailTabOTPFetcher


def _make_session(visible_text: str = "") -> MagicMock:
    """Build a fake browser_session with new_page / close_page / page.evaluate."""
    page = MagicMock()
    page.navigate = AsyncMock()
    page.evaluate = AsyncMock(return_value=visible_text)
    session = MagicMock()
    session.new_page = AsyncMock(return_value=page)
    session.close_page = AsyncMock()
    return session


class TestFetchCode:
    async def test_returns_code_when_in_email(self) -> None:
        session = _make_session(
            visible_text="Your Snapchat verification code is 123456. Use it within 10 minutes."
        )
        f = WebmailTabOTPFetcher(session, poll_interval=0.01, initial_render_delay=0.01)
        result = await f.fetch_code(sender_hint="snapchat.com", window_seconds=2)
        assert result == "123456"

    async def test_filters_by_digit_length(self) -> None:
        # 9-digit number shouldn't match the default (4–8 range).
        session = _make_session(visible_text="Tracking number 1234567890 — your package")
        f = WebmailTabOTPFetcher(session, poll_interval=0.01, initial_render_delay=0.01)
        result = await f.fetch_code(window_seconds=1)
        assert result is None

    async def test_respects_custom_digit_range(self) -> None:
        session = _make_session(visible_text="Code: 1234")
        f = WebmailTabOTPFetcher(session, poll_interval=0.01, initial_render_delay=0.01)
        # default range 4-8 includes 4 digits
        assert await f.fetch_code(window_seconds=1) == "1234"
        # narrower range 6-8 excludes 4
        assert await f.fetch_code(digits=(6, 8), window_seconds=1) is None

    async def test_returns_none_when_no_match_in_window(self) -> None:
        session = _make_session(visible_text="no code in this email body")
        f = WebmailTabOTPFetcher(session, poll_interval=0.01, initial_render_delay=0.01)
        result = await f.fetch_code(window_seconds=1)
        assert result is None

    async def test_closes_tab_even_on_match(self) -> None:
        session = _make_session(visible_text="code is 654321")
        f = WebmailTabOTPFetcher(session, poll_interval=0.01, initial_render_delay=0.01)
        await f.fetch_code(window_seconds=1)
        session.close_page.assert_called_once()

    async def test_closes_tab_on_timeout(self) -> None:
        session = _make_session(visible_text="")
        f = WebmailTabOTPFetcher(session, poll_interval=0.01, initial_render_delay=0.01)
        await f.fetch_code(window_seconds=1)
        session.close_page.assert_called_once()

    async def test_returns_none_if_new_page_fails(self) -> None:
        session = _make_session()
        session.new_page.side_effect = RuntimeError("no tab")
        f = WebmailTabOTPFetcher(session)
        result = await f.fetch_code(window_seconds=1)
        assert result is None


class TestFetchLink:
    async def test_extracts_reset_link(self) -> None:
        session = _make_session(
            visible_text=(
                "Hi Aditya, click here to reset your password: "
                "https://accounts.snapchat.com/reset?token=abc123 — "
                "this link expires in 1 hour."
            )
        )
        f = WebmailTabOTPFetcher(session, poll_interval=0.01, initial_render_delay=0.01)
        link = await f.fetch_link(sender_hint="snapchat.com", window_seconds=2)
        assert link is not None
        assert "snapchat.com/reset" in link
        assert "?token=abc123" in link

    async def test_returns_none_when_no_link(self) -> None:
        session = _make_session(visible_text="hello world")
        f = WebmailTabOTPFetcher(session, poll_interval=0.01, initial_render_delay=0.01)
        assert await f.fetch_link(window_seconds=1) is None


class TestSearchURL:
    def test_includes_sender_hint(self) -> None:
        f = WebmailTabOTPFetcher(MagicMock())
        url = f._search_url("snapchat.com")
        assert "from%3Asnapchat.com" in url or "from:snapchat.com" in url
        assert "newer_than" in url
        assert url.startswith("https://mail.google.com/mail/u/0/")

    def test_without_sender_hint(self) -> None:
        f = WebmailTabOTPFetcher(MagicMock())
        url = f._search_url(None)
        assert "from%3A" not in url
        assert "newer_than" in url


class TestProtocolShape:
    """Make sure the adapter satisfies the OTPFetcher Protocol."""

    def test_is_protocol_compliant(self) -> None:
        from rekey.ports.otp import OTPFetcher

        f = WebmailTabOTPFetcher(MagicMock())
        # Structural typing — these attributes must exist as callables.
        assert callable(f.fetch_code)
        assert callable(f.fetch_link)
        _ = OTPFetcher  # imported for the assertion that the type exists
        # We can't isinstance-check Protocols by default, but the methods
        # are there — that's the contract.
