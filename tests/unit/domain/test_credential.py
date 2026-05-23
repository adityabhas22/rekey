"""Tests for Credential and canonical_origin."""

from __future__ import annotations

import pytest

from rekey.domain.credential import Credential, VaultSource, canonical_origin


class TestCanonicalOrigin:
    @pytest.mark.parametrize(
        ("input_value", "expected"),
        [
            ("github.com", "https://github.com"),
            ("https://github.com", "https://github.com"),
            ("https://github.com/", "https://github.com"),
            ("https://GitHub.com/login", "https://github.com"),
            ("https://github.com?ref=foo", "https://github.com"),
            ("https://github.com#anchor", "https://github.com"),
            ("http://example.com", "http://example.com"),
            ("  github.com  ", "https://github.com"),
        ],
    )
    def test_normalizes(self, input_value: str, expected: str) -> None:
        assert canonical_origin(input_value) == expected

    def test_raises_on_empty(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            canonical_origin("   ")


class TestCredential:
    def test_constructs(self) -> None:
        c = Credential(
            id="abc",
            source=VaultSource.ONEPASSWORD,
            origin="https://github.com",
            username="me@example.com",
        )
        assert c.composite_id == "1password::abc"
        assert c.host == "github.com"
        assert c.has_totp is False
        assert c.tags == ()

    def test_rejects_empty_id(self) -> None:
        with pytest.raises(ValueError, match="id must be non-empty"):
            Credential(
                id="",
                source=VaultSource.ONEPASSWORD,
                origin="https://github.com",
                username="me",
            )

    def test_rejects_non_canonical_origin(self) -> None:
        with pytest.raises(ValueError, match="must be canonical"):
            Credential(
                id="abc",
                source=VaultSource.ONEPASSWORD,
                origin="https://github.com/login",
                username="me",
            )

    def test_from_raw_normalizes(self) -> None:
        c = Credential.from_raw(
            id="abc",
            source=VaultSource.ONEPASSWORD,
            origin="https://GitHub.com/login",
            username="me",
        )
        assert c.origin == "https://github.com"

    def test_frozen(self) -> None:
        c = Credential(
            id="abc",
            source=VaultSource.ONEPASSWORD,
            origin="https://github.com",
            username="me",
        )
        with pytest.raises((AttributeError, TypeError)):
            c.username = "other"  # type: ignore[misc]

    def test_composite_id_disambiguates_across_sources(self) -> None:
        a = Credential(
            id="x",
            source=VaultSource.ONEPASSWORD,
            origin="https://github.com",
            username="me",
        )
        b = Credential(
            id="x",
            source=VaultSource.BITWARDEN,
            origin="https://github.com",
            username="me",
        )
        assert a.composite_id != b.composite_id
