"""LLM factory port — produces chat models for the browser agent."""

from __future__ import annotations

from typing import Any, Protocol


class LLMFactory(Protocol):
    """Creates LLM instances.

    Returns ``Any`` because we don't pin the consumer (``browser-use``) to a
    specific base class signature.
    """

    def make(
        self,
        provider: str | None = None,
        model: str | None = None,
    ) -> Any:
        """Return a chat model. If ``provider`` is ``None``, the adapter is
        responsible for auto-detection (e.g. from environment variables).
        """
        ...
