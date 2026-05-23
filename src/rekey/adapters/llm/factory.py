"""LLM factory — produces browser-use-compatible chat models for any provider.

We re-use browser-use's own multi-provider abstraction rather than wiring up
LiteLLM / Agents-SDK on top. All our LLM calls happen inside browser-use's
agent loop, so a second abstraction would be redundant.

The chat-model classes are lazy-loaded so unit tests can inject fakes via
the ``factories`` constructor argument.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any


class UnknownLLMProvider(Exception):
    """The requested provider has no factory mapping."""


class NoLLMConfigured(Exception):
    """No API keys found in environment and no provider specified."""


# Env-var → provider mapping for auto-detection, in priority order.
_AUTO_DETECT_ORDER: list[tuple[str, str]] = [
    ("ANTHROPIC_API_KEY", "anthropic"),
    ("GOOGLE_API_KEY", "google"),
    ("OPENAI_API_KEY", "openai"),
]

# Default model per provider — overridable via the `model` arg.
_DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-5.5",
    "google": "gemini-2.5-flash",
    "ollama": "qwen2.5:32b",
}


class BrowserUseLLMFactory:
    """Creates LLM instances via browser-use's built-in multi-provider abstraction.

    Implements :class:`rekey.ports.LLMFactory`.
    """

    def __init__(
        self,
        *,
        factories: dict[str, Callable[..., Any]] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self._factories_override = factories
        # Treat env as a plain dict for testability — we don't mutate it.
        self._env: dict[str, str] = dict(env if env is not None else os.environ)

    def make(
        self,
        provider: str | None = None,
        model: str | None = None,
    ) -> Any:
        chosen = (provider or self._auto_detect_provider() or "").lower().strip()
        if not chosen:
            raise NoLLMConfigured(
                "No LLM provider configured. Set one of ANTHROPIC_API_KEY / "
                "GOOGLE_API_KEY / OPENAI_API_KEY, or REKEY_LLM_PROVIDER=ollama "
                "for a local model."
            )
        factories = self._factories()
        if chosen not in factories:
            raise UnknownLLMProvider(
                f"unknown LLM provider {chosen!r}; available: {sorted(factories)}"
            )
        resolved_model = model or _DEFAULT_MODELS.get(chosen)
        if resolved_model is None:
            raise UnknownLLMProvider(f"no default model registered for {chosen!r}")
        return factories[chosen](model=resolved_model)

    # ---- internals ----

    def _auto_detect_provider(self) -> str | None:
        explicit = self._env.get("REKEY_LLM_PROVIDER")
        if explicit:
            return explicit
        for env_var, provider in _AUTO_DETECT_ORDER:
            if self._env.get(env_var):
                return provider
        return None

    def _factories(self) -> dict[str, Callable[..., Any]]:
        if self._factories_override is not None:
            return self._factories_override
        # Lazy import — browser-use is heavy.
        from browser_use.llm import ChatAnthropic, ChatGoogle, ChatOpenAI

        result: dict[str, Callable[..., Any]] = {
            "anthropic": ChatAnthropic,
            "google": ChatGoogle,
            "openai": ChatOpenAI,
        }
        try:
            from browser_use.llm import ChatOllama  # not always present
            result["ollama"] = ChatOllama
        except ImportError:
            pass
        return result
