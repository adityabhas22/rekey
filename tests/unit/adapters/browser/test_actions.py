"""Tests for the verify_origin helper in actions.py.

The full custom-action wiring requires a real browser-use Controller and is
covered by the live integration test (see SETUP.md). Here we test the
origin-validation invariant in isolation.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from rekey.adapters.browser.actions import WrongOriginError, verify_origin


@pytest.mark.parametrize(
    ("current", "expected", "should_pass"),
    [
        ("https://github.com/settings/admin", "https://github.com", True),
        ("https://github.com", "https://github.com", True),
        ("https://GitHub.com/login", "https://github.com", True),     # canonicalized
        ("https://evil.com/?ref=github.com", "https://github.com", False),
        # Same registrable domain is now accepted (Fitbit reset link case):
        ("https://api.github.com", "https://github.com", True),
        ("https://www.fitbit.com/passwordReset", "https://accounts.fitbit.com", True),
        # Different parent domain still rejected:
        ("https://github.com.evil.com", "https://github.com", False),
        ("", "https://github.com", False),
    ],
)
async def test_verify_origin(current: str, expected: str, should_pass: bool) -> None:
    browser_session = AsyncMock()
    browser_session.get_current_page_url.return_value = current
    if should_pass:
        await verify_origin(browser_session, expected)
    else:
        with pytest.raises(WrongOriginError):
            await verify_origin(browser_session, expected)


async def test_verify_origin_no_url() -> None:
    browser_session = AsyncMock()
    browser_session.get_current_page_url.return_value = None
    with pytest.raises(WrongOriginError, match="could not determine"):
        await verify_origin(browser_session, "https://github.com")
