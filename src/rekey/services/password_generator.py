"""Cryptographically-secure password generation respecting :class:`PasswordPolicy`."""

from __future__ import annotations

import secrets
import string

from rekey.domain.policy import PasswordPolicy


def _without_forbidden(s: str, forbidden: frozenset[str]) -> str:
    return "".join(c for c in s if c not in forbidden)


def _secure_shuffle(items: list[str]) -> None:
    """Fisher–Yates shuffle using :mod:`secrets` for randomness."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_password(
    policy: PasswordPolicy | None = None,
    *,
    length: int | None = None,
) -> str:
    """Generate a cryptographically-secure password satisfying ``policy``.

    - At least one character from each required class is guaranteed.
    - Length is clamped to ``[policy.min_length, policy.max_length]``.
    - Characters in ``policy.forbidden`` are excluded from the alphabet.
    - Output is shuffled so the guaranteed chars don't sit at the start.
    """
    p = policy or PasswordPolicy.strong_default()
    target = length if length is not None else p.min_length
    target = max(p.min_length, min(target, p.max_length))

    lower = _without_forbidden(string.ascii_lowercase, p.forbidden)
    upper = _without_forbidden(string.ascii_uppercase, p.forbidden)
    digits = _without_forbidden(string.digits, p.forbidden)
    symbols = _without_forbidden(p.allowed_symbols, p.forbidden)

    # Validate that every required class has characters available.
    required: list[tuple[str, str]] = []
    if p.require_lower:
        required.append(("lowercase", lower))
    if p.require_upper:
        required.append(("uppercase", upper))
    if p.require_digit:
        required.append(("digit", digits))
    if p.require_symbol:
        required.append(("symbol", symbols))
    for name, chars in required:
        if not chars:
            raise ValueError(
                f"require_{name}=True but no {name} characters available "
                "(check `forbidden` / `allowed_symbols`)"
            )

    alphabet = lower + upper + digits + symbols
    if not alphabet:
        raise ValueError("policy resulted in empty alphabet")

    guaranteed = [secrets.choice(chars) for _, chars in required]
    if len(guaranteed) > target:
        raise ValueError(
            f"target length {target} cannot accommodate {len(guaranteed)} required classes"
        )

    remaining = target - len(guaranteed)
    chars_out = guaranteed + [secrets.choice(alphabet) for _ in range(remaining)]
    _secure_shuffle(chars_out)
    return "".join(chars_out)
