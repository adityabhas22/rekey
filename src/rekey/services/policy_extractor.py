"""Live extraction of password policy from a page's HTML.

Reads native form attributes (``minlength``, ``maxlength``, ``pattern``) plus
visible help-text hints. Designed to be cheap (DOM scrape only, no LLM call)
but extensible — when DOM signals are insufficient, the caller can fall back
to a mid-tier LLM extract step.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from rekey.domain.policy import PasswordPolicy

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExtractedPolicy:
    """Per-form policy hints we observed from the page."""

    min_length: int | None = None
    max_length: int | None = None
    requires_upper: bool | None = None
    requires_lower: bool | None = None
    requires_digit: bool | None = None
    requires_symbol: bool | None = None
    raw_hints: tuple[str, ...] = ()    # human-readable rules we matched

    def merge_with(self, default: PasswordPolicy) -> PasswordPolicy:
        """Apply the observed constraints on top of a default policy."""
        return PasswordPolicy(
            min_length=max(self.min_length or 0, default.min_length),
            max_length=min(self.max_length or default.max_length, default.max_length),
            require_upper=self.requires_upper if self.requires_upper is not None else default.require_upper,
            require_lower=self.requires_lower if self.requires_lower is not None else default.require_lower,
            require_digit=self.requires_digit if self.requires_digit is not None else default.require_digit,
            require_symbol=self.requires_symbol if self.requires_symbol is not None else default.require_symbol,
            allowed_symbols=default.allowed_symbols,
            forbidden=default.forbidden,
        )


_LENGTH_RE = re.compile(
    r"""
    (?:at\s*least|minimum|min\.?|>=|≥)\s*(?P<min1>\d{1,2})
    |(?P<min2>\d{1,2})\s*(?:or\s*more|\+|chars?\s*minimum)
    |(?:at\s*most|maximum|max\.?|<=|≤)\s*(?P<max1>\d{1,3})
    |(?P<max2>\d{1,3})\s*chars?\s*maximum
    """,
    re.IGNORECASE | re.VERBOSE,
)
_UPPER_RE = re.compile(r"(?i)\b(uppercase|capital)\b")
_LOWER_RE = re.compile(r"(?i)\b(lowercase|small)\b")
_DIGIT_RE = re.compile(r"(?i)\b(digit|number|numeric)\b")
_SYMBOL_RE = re.compile(r"(?i)\b(symbol|special|punctuation)\b")


def parse_help_text(text: str) -> ExtractedPolicy:
    """Parse free-form policy hints (e.g. "at least 8 characters, one digit")."""
    if not text:
        return ExtractedPolicy()
    hints: list[str] = []
    mn: int | None = None
    mx: int | None = None
    for m in _LENGTH_RE.finditer(text):
        for k in ("min1", "min2"):
            if m.group(k):
                v = int(m.group(k))
                if 4 <= v <= 64:
                    mn = max(mn or 0, v)
                    hints.append(f"min_length={v}")
        for k in ("max1", "max2"):
            if m.group(k):
                v = int(m.group(k))
                if 4 <= v <= 256:
                    mx = min(mx, v) if mx else v
                    hints.append(f"max_length={v}")
    needs_upper = bool(_UPPER_RE.search(text)) or None
    needs_lower = bool(_LOWER_RE.search(text)) or None
    needs_digit = bool(_DIGIT_RE.search(text)) or None
    needs_symbol = bool(_SYMBOL_RE.search(text)) or None
    return ExtractedPolicy(
        min_length=mn,
        max_length=mx,
        requires_upper=needs_upper,
        requires_lower=needs_lower,
        requires_digit=needs_digit,
        requires_symbol=needs_symbol,
        raw_hints=tuple(hints),
    )


def parse_form_attrs(
    *,
    minlength: int | str | None = None,
    maxlength: int | str | None = None,
    pattern: str | None = None,
) -> ExtractedPolicy:
    """Parse the password input's HTML attributes."""

    def _int(x: int | str | None) -> int | None:
        if x is None:
            return None
        try:
            v = int(x)
        except (TypeError, ValueError):
            return None
        return v if v > 0 else None

    mn = _int(minlength)
    mx = _int(maxlength)
    hints = []
    if mn:
        hints.append(f"minlength={mn}")
    if mx:
        hints.append(f"maxlength={mx}")
    if pattern:
        hints.append(f"pattern={pattern}")
    return ExtractedPolicy(min_length=mn, max_length=mx, raw_hints=tuple(hints))
