"""Password generation policy."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """Per-site rules a generated new password must satisfy.

    Defaults are deliberately strong-generic; sites can tighten via parsed
    ``passwordrules`` attribute or LLM-extracted hints.
    """

    min_length: int = 20
    max_length: int = 64
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    allowed_symbols: str = "!@#$%^&*-_=+[]{}:,.?"
    forbidden: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.min_length < 8:
            raise ValueError(f"min_length must be >= 8, got {self.min_length}")
        if self.max_length < self.min_length:
            raise ValueError(
                f"max_length ({self.max_length}) must be >= min_length ({self.min_length})"
            )
        if self.require_symbol and not self.allowed_symbols:
            raise ValueError("require_symbol=True but allowed_symbols is empty")

    @classmethod
    def strong_default(cls) -> PasswordPolicy:
        """20 chars, all four character classes."""
        return cls()

    @classmethod
    def conservative(cls) -> PasswordPolicy:
        """For sites with strict legacy rules: 16 chars, narrower symbol set."""
        return cls(min_length=16, max_length=32, allowed_symbols="!@#$_")
