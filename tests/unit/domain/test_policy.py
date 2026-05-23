"""Tests for PasswordPolicy."""

from __future__ import annotations

import pytest

from rekey.domain.policy import PasswordPolicy


def test_strong_default() -> None:
    p = PasswordPolicy.strong_default()
    assert p.min_length == 20
    assert p.require_symbol
    assert p.allowed_symbols


def test_conservative() -> None:
    p = PasswordPolicy.conservative()
    assert p.min_length == 16
    assert p.max_length == 32


def test_rejects_short_min_length() -> None:
    with pytest.raises(ValueError, match="min_length must be >= 8"):
        PasswordPolicy(min_length=4)


def test_rejects_inverted_lengths() -> None:
    with pytest.raises(ValueError, match="max_length"):
        PasswordPolicy(min_length=20, max_length=10)


def test_rejects_empty_symbols_when_required() -> None:
    with pytest.raises(ValueError, match="allowed_symbols"):
        PasswordPolicy(require_symbol=True, allowed_symbols="")


def test_no_symbols_when_not_required_is_ok() -> None:
    p = PasswordPolicy(require_symbol=False, allowed_symbols="")
    assert not p.require_symbol


def test_frozen() -> None:
    p = PasswordPolicy()
    with pytest.raises((AttributeError, TypeError)):
        p.min_length = 30  # type: ignore[misc]
