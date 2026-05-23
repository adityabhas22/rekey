"""Per-domain known password policies — the "things that bite" database.

Many sites silently truncate, ban specific characters, or have other rules
that aren't surfaced in the UI. Hardcoding the known offenders saves an
entire rotation attempt-and-fail cycle.

Sourced from dumbpasswordrules.com and the v0.2 spec research. Extend by
adding entries here (and a test if the rule is unusual).
"""

from __future__ import annotations

from rekey.domain.policy import PasswordPolicy


def get(host: str) -> PasswordPolicy | None:
    """Return a known policy for ``host`` (or its parent domain), or None."""
    h = host.lower()
    # Try exact match first, then progressively dropped subdomains.
    while h:
        if h in _DB:
            return _DB[h]
        if "." not in h:
            break
        h = h.split(".", 1)[1]
    return None


# Conservative defaults — these are minimums from the research.
# (Add more sites as encountered; tests should pin the unusual ones.)
_DB: dict[str, PasswordPolicy] = {
    # Bank of America: silently truncates at 20.
    "bankofamerica.com": PasswordPolicy(
        min_length=12, max_length=20, allowed_symbols="!@#$_-",
    ),
    # Chase: 32 max, no consecutive same-class chars (not enforceable in generator,
    # rely on iterative regen). We just cap length safely.
    "chase.com": PasswordPolicy(min_length=12, max_length=32),
    # Cigna: 12 max, narrow specials.
    "cigna.com": PasswordPolicy(min_length=8, max_length=12, allowed_symbols="!@#$"),
    # Microsoft work accounts: 16 max.
    "microsoft.com": PasswordPolicy(min_length=12, max_length=16),
    # PayPal: 20 max.
    "paypal.com": PasswordPolicy(min_length=12, max_length=20),
    # Best Buy: known to silently truncate.
    "bestbuy.com": PasswordPolicy(min_length=12, max_length=20),
    # Snapchat: minimum 8, otherwise permissive but rate-limits aggressively.
    "snapchat.com": PasswordPolicy(min_length=12, max_length=20),
    # Battle.net: no special characters per their own rule.
    "battle.net": PasswordPolicy(
        min_length=12,
        max_length=16,
        require_symbol=False,
        allowed_symbols="",
    ),
    # Fitbit: standard, 8 minimum, no extreme rules known.
    "fitbit.com": PasswordPolicy(min_length=12, max_length=32),
    # Google: minimum 8, 100 max.
    "google.com": PasswordPolicy(min_length=12, max_length=64),
    # Apple ID: 8 min, must include letter + number + upper + lower.
    "apple.com": PasswordPolicy(min_length=12, max_length=64),
}
