"""Tests for HIBPChecker."""

from __future__ import annotations

import httpx
import pytest
import respx

from rekey.adapters.breach.hibp import HIBP_RANGE_URL, HIBPChecker

# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
_PASSWORD_PREFIX = "5BAA6"
_PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


@respx.mock
def test_known_compromised_password() -> None:
    respx.get(HIBP_RANGE_URL.format(prefix=_PASSWORD_PREFIX)).mock(
        return_value=httpx.Response(
            200,
            text=f"{_PASSWORD_SUFFIX}:12345678\nOTHER:1\n",
        )
    )
    with HIBPChecker() as checker:
        assert checker.count_breaches("password") == 12345678


@respx.mock
def test_password_not_in_breach() -> None:
    respx.get(HIBP_RANGE_URL.format(prefix=_PASSWORD_PREFIX)).mock(
        return_value=httpx.Response(200, text="OTHERSUFFIX:1\n")
    )
    with HIBPChecker() as checker:
        assert checker.count_breaches("password") == 0


def test_empty_password_returns_zero_without_hitting_api() -> None:
    # No respx mock — any HTTP call would error out, but empty path skips it.
    with HIBPChecker() as checker:
        assert checker.count_breaches("") == 0


@respx.mock
def test_sends_padding_header_by_default() -> None:
    route = respx.get(HIBP_RANGE_URL.format(prefix=_PASSWORD_PREFIX)).mock(
        return_value=httpx.Response(200, text="\n")
    )
    with HIBPChecker() as checker:
        checker.count_breaches("password")
    assert route.calls.last.request.headers.get("Add-Padding") == "true"


@respx.mock
def test_can_disable_padding() -> None:
    route = respx.get(HIBP_RANGE_URL.format(prefix=_PASSWORD_PREFIX)).mock(
        return_value=httpx.Response(200, text="\n")
    )
    with HIBPChecker(add_padding=False) as checker:
        checker.count_breaches("password")
    assert "Add-Padding" not in route.calls.last.request.headers


@respx.mock
def test_raises_on_http_error() -> None:
    respx.get(HIBP_RANGE_URL.format(prefix=_PASSWORD_PREFIX)).mock(
        return_value=httpx.Response(500)
    )
    with HIBPChecker() as checker, pytest.raises(httpx.HTTPStatusError):
        checker.count_breaches("password")


@pytest.mark.integration
def test_real_hibp_known_compromised() -> None:
    """Integration test: 'password' must return high breach count from real HIBP."""
    with HIBPChecker() as checker:
        count = checker.count_breaches("password")
        assert count > 1_000_000, f"expected millions of breaches for 'password', got {count}"
