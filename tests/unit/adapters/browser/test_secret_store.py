"""Tests for SecretStore."""

from __future__ import annotations

import pytest

from rekey.adapters.browser.secret_store import (
    RotationSecrets,
    SecretNotFound,
    SecretStore,
)


def _rec(credential_id: str = "abc") -> RotationSecrets:
    return RotationSecrets(
        credential_id=credential_id,
        expected_origin="https://github.com",
        current_password="oldpw",
        new_password="newpw",
    )


class TestPutAndGet:
    def test_round_trip(self) -> None:
        store = SecretStore()
        rec = _rec()
        store.put(rec)
        assert store.get("abc") == rec
        assert "abc" in store
        assert len(store) == 1

    def test_get_missing_raises_secret_not_found(self) -> None:
        store = SecretStore()
        with pytest.raises(SecretNotFound):
            store.get("missing")

    def test_secret_not_found_is_key_error(self) -> None:
        """SecretNotFound subclasses KeyError so catch-KeyError code still works."""
        store = SecretStore()
        with pytest.raises(KeyError):
            store.get("missing")


class TestClear:
    def test_clear_specific(self) -> None:
        store = SecretStore()
        store.put(_rec("a"))
        store.put(_rec("b"))
        store.clear("a")
        assert "a" not in store
        assert "b" in store

    def test_clear_missing_is_noop(self) -> None:
        store = SecretStore()
        store.clear("nonexistent")  # should not raise

    def test_clear_all(self) -> None:
        store = SecretStore()
        store.put(_rec("a"))
        store.put(_rec("b"))
        store.clear_all()
        assert len(store) == 0


class TestImmutability:
    def test_records_are_frozen(self) -> None:
        rec = _rec()
        with pytest.raises((AttributeError, TypeError)):
            rec.current_password = "tampered"  # type: ignore[misc]
