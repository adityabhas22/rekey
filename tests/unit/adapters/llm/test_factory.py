"""Tests for BrowserUseLLMFactory."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from rekey.adapters.llm.factory import (
    BrowserUseLLMFactory,
    NoLLMConfigured,
    UnknownLLMProvider,
)


class FakeChat:
    """Stand-in for browser-use's ChatXxx classes."""

    def __init__(self, model: str) -> None:
        self.model = model


@pytest.fixture
def factories() -> dict[str, Callable[..., Any]]:
    return {
        "anthropic": FakeChat,
        "openai": FakeChat,
        "google": FakeChat,
        "ollama": FakeChat,
    }


class TestAutoDetect:
    def test_anthropic_has_priority(self, factories: dict[str, Callable[..., Any]]) -> None:
        env = {"ANTHROPIC_API_KEY": "x", "OPENAI_API_KEY": "y"}
        chat = BrowserUseLLMFactory(factories=factories, env=env).make()
        assert chat.model == "claude-sonnet-4-6"

    def test_google_when_no_anthropic(self, factories: dict[str, Callable[..., Any]]) -> None:
        env = {"GOOGLE_API_KEY": "x", "OPENAI_API_KEY": "y"}
        chat = BrowserUseLLMFactory(factories=factories, env=env).make()
        assert chat.model == "gemini-2.5-flash"

    def test_openai_when_only_one(self, factories: dict[str, Callable[..., Any]]) -> None:
        env = {"OPENAI_API_KEY": "x"}
        chat = BrowserUseLLMFactory(factories=factories, env=env).make()
        assert chat.model == "gpt-5.5"

    def test_explicit_override_via_rekey_env(
        self, factories: dict[str, Callable[..., Any]]
    ) -> None:
        env = {"ANTHROPIC_API_KEY": "x", "REKEY_LLM_PROVIDER": "ollama"}
        chat = BrowserUseLLMFactory(factories=factories, env=env).make()
        assert chat.model == "qwen2.5:32b"

    def test_no_keys_raises(self, factories: dict[str, Callable[..., Any]]) -> None:
        with pytest.raises(NoLLMConfigured, match="No LLM provider"):
            BrowserUseLLMFactory(factories=factories, env={}).make()


class TestExplicitArgs:
    def test_explicit_provider_arg(self, factories: dict[str, Callable[..., Any]]) -> None:
        f = BrowserUseLLMFactory(factories=factories, env={})
        chat = f.make(provider="google")
        assert chat.model == "gemini-2.5-flash"

    def test_explicit_model_overrides_default(
        self, factories: dict[str, Callable[..., Any]]
    ) -> None:
        f = BrowserUseLLMFactory(factories=factories, env={})
        chat = f.make(provider="anthropic", model="claude-opus-4-7")
        assert chat.model == "claude-opus-4-7"


class TestErrors:
    def test_unknown_provider_raises(
        self, factories: dict[str, Callable[..., Any]]
    ) -> None:
        f = BrowserUseLLMFactory(factories=factories, env={})
        with pytest.raises(UnknownLLMProvider, match="unknown"):
            f.make(provider="nonexistent")
