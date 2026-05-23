"""Per-domain site recipes + memory of past rotations.

A *recipe* captures everything we've learned about a specific host's
password-rotation flow: where the change-password form lives, the URL of
the forgot-password page, which selectors work for the email/code fields,
the password policy, etc. Recipes live in
``~/.rekey/recipes/<domain>.yaml`` and are auto-created on first run.

A *memory* record tracks per-attempt outcomes (success/failure counts,
last-success/last-failure timestamps, the last error message). The state
machine uses memory to decide:

  - Should we trust the cached recipe, or re-learn?
  - Is this site in a cooldown after repeated failures?
  - Which strategy worked last time? (try that first)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)


BotIntensity = Literal["light", "moderate", "severe", "unknown"]
Strategy = Literal["in-session", "forgot-password", "manual-handoff"]


@dataclass
class SiteMemory:
    """Outcomes we've observed for one site."""

    success_count: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    last_success_ts: float | None = None
    last_failure_ts: float | None = None
    last_failure_reason: str | None = None
    last_successful_strategy: Strategy | None = None
    cooldown_until_ts: float | None = None


@dataclass
class SiteRecipe:
    """Static knowledge + learned memory for one host."""

    domain: str
    display_name: str = ""
    bot_intensity: BotIntensity = "unknown"
    strategies: list[Strategy] = field(
        default_factory=lambda: ["in-session", "forgot-password", "manual-handoff"]
    )
    change_password_url: str | None = None
    forgot_password_url: str | None = None
    # selectors[field_name] is a list of CSS selectors to try in order
    selectors: dict[str, list[str]] = field(default_factory=dict)
    expected_otp_senders: list[str] = field(default_factory=list)
    memory: SiteMemory = field(default_factory=SiteMemory)

    def in_cooldown(self) -> bool:
        if self.memory.cooldown_until_ts is None:
            return False
        return time.time() < self.memory.cooldown_until_ts

    def preferred_strategy_order(self) -> list[Strategy]:
        """Return strategies in the order we should try them now."""
        # If a strategy worked recently, try it first.
        ordered = list(self.strategies)
        if self.memory.last_successful_strategy in ordered:
            ordered.remove(self.memory.last_successful_strategy)
            ordered.insert(0, self.memory.last_successful_strategy)
        return ordered


class RecipeStore:
    """JSON-on-disk per-domain recipe registry."""

    def __init__(self, path: Path | str | None = None) -> None:
        self._dir = Path(path or (Path.home() / ".rekey" / "recipes"))
        self._dir.mkdir(parents=True, exist_ok=True)

    def get(self, domain: str) -> SiteRecipe | None:
        f = self._path_for(domain)
        if not f.exists():
            return None
        try:
            raw = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Recipe %s unreadable (%s); ignoring", f, e)
            return None
        return _recipe_from_dict(raw)

    def put(self, recipe: SiteRecipe) -> None:
        f = self._path_for(recipe.domain)
        f.write_text(json.dumps(_recipe_to_dict(recipe), indent=2))

    def record_success(self, domain: str, *, strategy: Strategy) -> None:
        recipe = self.get(domain) or SiteRecipe(domain=domain)
        recipe.memory.success_count += 1
        recipe.memory.consecutive_failures = 0
        recipe.memory.last_success_ts = time.time()
        recipe.memory.last_successful_strategy = strategy
        recipe.memory.cooldown_until_ts = None
        self.put(recipe)

    def record_failure(self, domain: str, *, reason: str, cooldown_seconds: int = 0) -> None:
        recipe = self.get(domain) or SiteRecipe(domain=domain)
        recipe.memory.failure_count += 1
        recipe.memory.consecutive_failures += 1
        recipe.memory.last_failure_ts = time.time()
        recipe.memory.last_failure_reason = reason
        if cooldown_seconds > 0:
            recipe.memory.cooldown_until_ts = time.time() + cooldown_seconds
        # Auto-escalating cooldown after repeated failures.
        elif recipe.memory.consecutive_failures >= 3:
            recipe.memory.cooldown_until_ts = time.time() + 86400  # 24h
        self.put(recipe)

    # ----- internals -----

    def _path_for(self, domain: str) -> Path:
        safe = domain.replace("/", "_").replace(":", "_")
        return self._dir / f"{safe}.json"


def _recipe_to_dict(r: SiteRecipe) -> dict:
    d = asdict(r)
    return d


def _recipe_from_dict(d: dict) -> SiteRecipe:
    mem = d.get("memory") or {}
    return SiteRecipe(
        domain=d["domain"],
        display_name=d.get("display_name", ""),
        bot_intensity=d.get("bot_intensity", "unknown"),
        strategies=list(d.get("strategies", ["in-session", "forgot-password", "manual-handoff"])),
        change_password_url=d.get("change_password_url"),
        forgot_password_url=d.get("forgot_password_url"),
        selectors=dict(d.get("selectors") or {}),
        expected_otp_senders=list(d.get("expected_otp_senders") or []),
        memory=SiteMemory(**mem) if mem else SiteMemory(),
    )
