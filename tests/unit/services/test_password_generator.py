"""Tests for the password generator."""

from __future__ import annotations

import string

import pytest

from rekey.domain.policy import PasswordPolicy
from rekey.services.password_generator import generate_password


class TestLength:
    def test_default_length(self) -> None:
        pw = generate_password()
        assert len(pw) == 20

    def test_explicit_length(self) -> None:
        pw = generate_password(length=32)
        assert len(pw) == 32

    def test_clamps_below_min(self) -> None:
        pw = generate_password(length=5)  # below default min_length=20
        assert len(pw) == 20

    def test_clamps_above_max(self) -> None:
        pw = generate_password(length=200)  # above default max_length=64
        assert len(pw) == 64


class TestCharacterClasses:
    def test_contains_each_required_class(self) -> None:
        pw = generate_password()
        assert any(c.isupper() for c in pw), pw
        assert any(c.islower() for c in pw), pw
        assert any(c.isdigit() for c in pw), pw
        symbols = PasswordPolicy.strong_default().allowed_symbols
        assert any(c in symbols for c in pw), pw

    def test_no_forbidden_chars(self) -> None:
        policy = PasswordPolicy(forbidden=frozenset("ABCabc123"))
        pw = generate_password(policy)
        for c in "ABCabc123":
            assert c not in pw

    def test_only_lowercase_required(self) -> None:
        policy = PasswordPolicy(
            require_upper=False,
            require_lower=True,
            require_digit=False,
            require_symbol=False,
            allowed_symbols="",
        )
        pw = generate_password(policy)
        assert any(c.islower() for c in pw)
        assert len(pw) == 20

    def test_conservative_uses_narrow_symbols(self) -> None:
        pw = generate_password(PasswordPolicy.conservative())
        assert len(pw) == 16
        for c in pw:
            if c in string.punctuation:
                assert c in PasswordPolicy.conservative().allowed_symbols


class TestValidation:
    def test_raises_when_required_class_all_forbidden(self) -> None:
        policy = PasswordPolicy(
            forbidden=frozenset(string.ascii_lowercase),
        )
        with pytest.raises(ValueError, match="lowercase"):
            generate_password(policy)


class TestUniqueness:
    def test_passwords_are_unique(self) -> None:
        # Cryptographically random — practically all distinct in a small batch.
        passwords = {generate_password() for _ in range(50)}
        assert len(passwords) == 50
