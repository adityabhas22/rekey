"""Read SMS / iMessage codes directly from macOS `chat.db`.

Continuity forwards SMS from the user's iPhone to the Mac's Messages app.
Those messages live in ``~/Library/Messages/chat.db`` (SQLite). With Full
Disk Access on the Python interpreter, we can read the DB live (read-only
URI mode) and extract OTP codes within seconds of arrival.

Permissions: System Settings → Privacy & Security → Full Disk Access →
add Terminal / iTerm / your packaged binary.

Apple stores message dates in Core Data epoch (nanoseconds since
2001-01-01 UTC). We convert.

Body text lives in ``message.text`` for plain SMS, OR in
``message.attributedBody`` for iMessage rich content (NSKeyedArchiver
blob). We try ``text`` first, fall back to extracting text from the blob
via a known byte pattern.
"""

from __future__ import annotations

import asyncio
import logging
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


# Core Data epoch (2001-01-01 UTC) in Unix seconds.
_COREDATA_EPOCH_OFFSET = 978307200

# Default path on macOS.
_DEFAULT_DB_PATH = Path.home() / "Library" / "Messages" / "chat.db"

# OTP regex — 4–8 contiguous digits at a digit boundary.
_OTP_RE = re.compile(r"(?<!\d)(\d{4,8})(?!\d)")

# Cue words near a digit cluster boost confidence.
_CUE_RE = re.compile(
    r"(?i)\b(verification|verify|otp|code|passcode|one[\s-]?time|"
    r"security|2fa|two[-\s]?factor|sign[-\s]?in|login|authentic)\w*"
)


@dataclass(frozen=True, slots=True)
class SMSMessage:
    """One parsed SMS / iMessage from chat.db."""

    rowid: int
    received_unix: float
    sender: str
    text: str
    is_imessage: bool


def _coredata_to_unix(ns: int | float | None) -> float:
    """Convert Messages.app's nanosecond-Core-Data timestamp to Unix seconds."""
    if not ns:
        return 0.0
    return ns / 1e9 + _COREDATA_EPOCH_OFFSET


def _extract_text_from_attributedbody(blob: bytes | None) -> str:
    """Best-effort extraction of plain text from an NSKeyedArchiver blob.

    iMessage rich content uses NSAttributedString. The canonical robust path
    is the `imessage_tools` library. For our OTP use case a forgiving regex
    over the raw bytes catches the text segment in nearly all cases.
    """
    if not blob:
        return ""
    try:
        # The text body is usually right after the marker bytes `\x01+\x00\x00\x00`.
        # We don't need a perfect parse — just enough to find digits + cue words.
        text = blob.decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return ""
    # Strip control chars; collapse runs of non-printable.
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", " ", text)


class ChatDbReader:
    """Polls ``~/Library/Messages/chat.db`` for new inbound messages.

    Uses SQLite read-only URI mode so it never locks the DB. Messages.app
    must be open or have been opened recently for Continuity SMS to land
    in chat.db.
    """

    def __init__(
        self,
        *,
        db_path: Path | str | None = None,
        poll_interval: float = 0.75,
    ) -> None:
        self._db_path = Path(db_path or _DEFAULT_DB_PATH)
        self._poll_interval = poll_interval

    def available(self) -> bool:
        """Check that the DB exists and is readable."""
        if not self._db_path.exists():
            return False
        try:
            with self._connect() as con:
                con.execute("SELECT 1 FROM message LIMIT 1")
            return True
        except sqlite3.Error as e:
            logger.warning("chat.db not readable (need Full Disk Access?): %s", e)
            return False

    async def wait_for_code(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 120,
        digits: tuple[int, int] = (4, 8),
    ) -> str | None:
        """Poll until an OTP matching the cue heuristic arrives, or timeout."""
        deadline = time.monotonic() + window_seconds
        cutoff_unix = time.time()  # only consider messages newer than this
        while time.monotonic() < deadline:
            try:
                msgs = self._fetch_recent(since_unix=cutoff_unix)
            except sqlite3.Error as e:
                logger.warning("chat.db read failed: %s", e)
                msgs = []

            best = self._best_otp_match(msgs, sender_hint=sender_hint, digits=digits)
            if best is not None:
                return best

            await asyncio.sleep(self._poll_interval)

        return None

    async def wait_for_link(
        self,
        *,
        sender_hint: str | None = None,
        window_seconds: int = 180,
    ) -> str | None:
        """SMS magic links are uncommon, but supported for symmetry."""
        link_re = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
        deadline = time.monotonic() + window_seconds
        cutoff_unix = time.time()
        while time.monotonic() < deadline:
            try:
                msgs = self._fetch_recent(since_unix=cutoff_unix)
            except sqlite3.Error as e:
                logger.warning("chat.db read failed: %s", e)
                msgs = []
            for m in msgs:
                if sender_hint and sender_hint.lower() not in m.text.lower() and sender_hint.lower() not in m.sender.lower():
                    continue
                match = link_re.search(m.text)
                if match:
                    return match.group(0)
            await asyncio.sleep(self._poll_interval)
        return None

    # ----- internals -----

    def _connect(self) -> sqlite3.Connection:
        uri = f"file:{self._db_path}?mode=ro&immutable=0"
        return sqlite3.connect(uri, uri=True, timeout=2.0)

    def _fetch_recent(self, *, since_unix: float, limit: int = 50) -> list[SMSMessage]:
        """Return inbound messages received since ``since_unix``, newest first."""
        # Convert Unix to Core Data nanoseconds.
        since_ns = int((since_unix - _COREDATA_EPOCH_OFFSET) * 1e9)
        sql = """
            SELECT m.ROWID, m.date, COALESCE(h.id, '') AS sender,
                   m.text, m.attributedBody, m.service
              FROM message m
              LEFT JOIN handle h ON m.handle_id = h.ROWID
             WHERE m.is_from_me = 0
               AND m.date > ?
             ORDER BY m.date DESC
             LIMIT ?
        """
        out: list[SMSMessage] = []
        with self._connect() as con:
            for row in con.execute(sql, (since_ns, limit)):
                rowid, date_ns, sender, text, attr, service = row
                body = text or _extract_text_from_attributedbody(attr)
                if not body:
                    continue
                out.append(
                    SMSMessage(
                        rowid=int(rowid),
                        received_unix=_coredata_to_unix(date_ns),
                        sender=sender,
                        text=body,
                        is_imessage=str(service or "").lower() == "imessage",
                    )
                )
        return out

    def _best_otp_match(
        self,
        msgs: list[SMSMessage],
        *,
        sender_hint: str | None,
        digits: tuple[int, int],
    ) -> str | None:
        """Score each message and return the highest-scoring OTP."""
        best_code: str | None = None
        best_score = -1
        for m in msgs:
            score = 0
            if sender_hint:
                if sender_hint.lower() in m.sender.lower():
                    score += 8
                if sender_hint.lower() in m.text.lower():
                    score += 4
            if _CUE_RE.search(m.text):
                score += 5
            for match in _OTP_RE.finditer(m.text):
                code = match.group(1)
                if not (digits[0] <= len(code) <= digits[1]):
                    continue
                # Penalize obvious non-OTPs (years, common round numbers)
                if 1900 <= int(code) <= 2100 and len(code) == 4:
                    continue
                if code in {"0000", "1234", "9999"}:
                    continue
                # Prefer 6-digit codes (most common OTP length)
                local_score = score + (2 if len(code) == 6 else 0)
                if local_score > best_score:
                    best_score = local_score
                    best_code = code
        return best_code if best_score >= 5 else None  # require at least one cue
