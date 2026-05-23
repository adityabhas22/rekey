"""Iterative password generation with policy refinement.

Workflow:

  1. Look up a static known-policy for the host (BofA truncates at 20, etc.).
  2. Optionally augment with a live-parsed policy from form attrs / help text.
  3. Generate a candidate.
  4. Submit. If the site rejects with a "doesn't meet policy" hint, refine
     the policy from the error text and re-roll. Cap at N attempts.

This module is the *generation* half; the calling state machine performs
the submit-and-observe loop.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from rekey.domain.policy import PasswordPolicy
from rekey.services import policy_database
from rekey.services.password_generator import generate_password
from rekey.services.policy_extractor import ExtractedPolicy

logger = logging.getLogger(__name__)

_MAX_REGEN_ATTEMPTS = 3


@dataclass
class GenerationOutcome:
    """Result of one generation call."""

    password: str
    policy: PasswordPolicy
    attempts: int                  # how many candidate passwords this iteration produced


def for_host(
    host: str,
    *,
    extracted: ExtractedPolicy | None = None,
) -> PasswordPolicy:
    """Build the policy to use for this host, combining static + live signals."""
    base = policy_database.get(host) or PasswordPolicy.strong_default()
    if extracted is None:
        return base
    return extracted.merge_with(base)


def refine_from_error(policy: PasswordPolicy, error_text: str) -> PasswordPolicy:
    """Tighten the policy in response to a server-side rejection message.

    Conservative — we only trust signals we can clearly parse. Returns the
    same policy if nothing actionable was found.
    """
    if not error_text:
        return policy

    text = error_text.lower()
    new_min = policy.min_length
    new_max = policy.max_length
    new_require_symbol = policy.require_symbol
    new_allowed = policy.allowed_symbols

    # Look for length corrections.
    m = re.search(r"(?:at\s*least|min(?:imum)?)\s*(\d{1,2})", text)
    if m:
        v = int(m.group(1))
        if 8 <= v <= 64 and v > new_min:
            logger.info("Refining min_length: %d → %d (from error)", new_min, v)
            new_min = v

    m = re.search(r"(?:at\s*most|max(?:imum)?|no\s*more\s*than)\s*(\d{1,3})", text)
    if m:
        v = int(m.group(1))
        if 8 <= v <= 256 and v < new_max:
            logger.info("Refining max_length: %d → %d (from error)", new_max, v)
            new_max = v

    if "no special" in text or "must not contain special" in text or "cannot contain special" in text:
        logger.info("Refining: dropping symbol requirement (from error)")
        new_require_symbol = False
        new_allowed = ""

    return PasswordPolicy(
        min_length=new_min,
        max_length=new_max,
        require_upper=policy.require_upper,
        require_lower=policy.require_lower,
        require_digit=policy.require_digit,
        require_symbol=new_require_symbol,
        allowed_symbols=new_allowed,
        forbidden=policy.forbidden,
    )


def generate_for_host(
    host: str,
    *,
    extracted: ExtractedPolicy | None = None,
) -> GenerationOutcome:
    """Generate the first-try password for the host."""
    policy = for_host(host, extracted=extracted)
    pw = generate_password(policy)
    return GenerationOutcome(password=pw, policy=policy, attempts=1)
