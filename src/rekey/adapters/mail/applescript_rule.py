"""Apple Mail.app rule + localhost HTTP receiver — provider-agnostic push OTP.

The user installs a Mail rule once (we ship the AppleScript) that POSTs
every incoming message to ``http://127.0.0.1:<port>/mail-event``. This
file runs the receiver and exposes an async ``wait_for_code`` that blocks
until a matching message arrives.

Setup the user must do (one-time):

  1. Open Mail.app → Mail menu → Settings → Rules → Add Rule.
  2. Conditions: ``Every Message``.
  3. Actions: ``Run AppleScript`` → ``Open in Finder...`` → pick the
     ``rekey-mail-handler.applescript`` we ship under ``docs/scripts/``.
  4. Click OK; Mail.app will save it to
     ``~/Library/Application Scripts/com.apple.mail/``.

The handler script posts ``{sender, subject, body}`` to localhost on the
rekey port. The receiver runs only while rekey is active; messages that
arrive while rekey is off are simply not seen (which is correct — we
only care about OTPs during a rotation).
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass

from fastapi import FastAPI, Request

logger = logging.getLogger(__name__)


_OTP_RE = re.compile(r"(?<!\d)(\d{4,8})(?!\d)")
_CUE_RE = re.compile(
    r"(?i)\b(verification|verify|otp|code|passcode|one[\s-]?time|"
    r"security|2fa|two[-\s]?factor|sign[-\s]?in|login|authentic)\w*"
)
_LINK_RE = re.compile(
    r"https?://[^\s<>\"']+(?:reset|verify|confirm|password|change|magic|token|auth)[^\s<>\"']*",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class MailEvent:
    received_unix: float
    sender: str
    subject: str
    body: str


class MailRuleReceiver:
    """In-process buffer for mail events POSTed by the Mail.app rule.

    Implements the receiver-half of the channel: register routes on a
    FastAPI app, store recent events, and provide async wait_for_* methods.
    """

    def __init__(self, *, retention_seconds: int = 600, max_events: int = 200) -> None:
        self._events: list[MailEvent] = []
        self._lock = asyncio.Lock()
        self._retention = retention_seconds
        self._max = max_events
        self._new_event = asyncio.Event()

    def register_routes(self, app: FastAPI) -> None:
        @app.post("/mail-event")
        async def receive(req: Request) -> dict[str, bool]:
            data = await req.form()
            event = MailEvent(
                received_unix=time.time(),
                sender=str(data.get("from", "")).strip(),
                subject=str(data.get("subject", "")).strip(),
                body=str(data.get("body", "")).strip(),
            )
            async with self._lock:
                self._events.append(event)
                self._prune_locked()
                self._new_event.set()
            return {"ok": True}

    async def wait_for_code(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 120,
        digits: tuple[int, int] = (4, 8),
    ) -> str | None:
        """Block until a matching OTP arrives or the window elapses."""
        deadline = time.monotonic() + window_seconds
        cutoff_unix = time.time()

        while time.monotonic() < deadline:
            async with self._lock:
                self._prune_locked()
                candidates = [e for e in self._events if e.received_unix >= cutoff_unix]
                self._new_event.clear()

            best = self._best_otp(candidates, sender_hint=sender_hint, digits=digits)
            if best is not None:
                return best

            timeout = deadline - time.monotonic()
            if timeout <= 0:
                break
            try:
                await asyncio.wait_for(self._new_event.wait(), timeout=min(timeout, 2.0))
            except asyncio.TimeoutError:
                pass

        return None

    async def wait_for_link(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 180,
    ) -> str | None:
        deadline = time.monotonic() + window_seconds
        cutoff_unix = time.time()
        while time.monotonic() < deadline:
            async with self._lock:
                self._prune_locked()
                candidates = [e for e in self._events if e.received_unix >= cutoff_unix]
                self._new_event.clear()

            for ev in sorted(candidates, key=lambda e: -e.received_unix):
                if sender_hint:
                    s = sender_hint.lower()
                    if s not in ev.sender.lower() and s not in ev.body.lower() and s not in ev.subject.lower():
                        continue
                match = _LINK_RE.search(ev.body) or _LINK_RE.search(ev.subject)
                if match:
                    return match.group(0)

            timeout = deadline - time.monotonic()
            if timeout <= 0:
                break
            try:
                await asyncio.wait_for(self._new_event.wait(), timeout=min(timeout, 2.0))
            except asyncio.TimeoutError:
                pass
        return None

    # ---- internals ----

    def _prune_locked(self) -> None:
        cutoff = time.time() - self._retention
        self._events = [e for e in self._events if e.received_unix >= cutoff][-self._max:]

    def _best_otp(
        self,
        events: list[MailEvent],
        *,
        sender_hint: str | None,
        digits: tuple[int, int],
    ) -> str | None:
        best_code: str | None = None
        best_score = -1
        for ev in events:
            score = 0
            if sender_hint:
                s = sender_hint.lower()
                if s in ev.sender.lower():
                    score += 8
                if s in ev.subject.lower():
                    score += 5
                if s in ev.body.lower():
                    score += 3
            if _CUE_RE.search(ev.subject) or _CUE_RE.search(ev.body):
                score += 5
            for body in (ev.subject, ev.body):
                for m in _OTP_RE.finditer(body):
                    code = m.group(1)
                    if not (digits[0] <= len(code) <= digits[1]):
                        continue
                    if 1900 <= int(code) <= 2100 and len(code) == 4:
                        continue
                    if code in {"0000", "1234", "9999"}:
                        continue
                    local = score + (2 if len(code) == 6 else 0)
                    if local > best_score:
                        best_score = local
                        best_code = code
        return best_code if best_score >= 5 else None
