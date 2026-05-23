"""FastAPI + SSE web dashboard — implements :class:`HandoffUI`.

A small HTTP service on ``127.0.0.1:7777`` showing live audit/rotation
events and prompting the user for approvals (CAPTCHA, 2FA, final submit).

Security
--------
- Binds to ``127.0.0.1`` only — never exposed to the network.
- CSRF token in an ``HttpOnly`` cookie; required on every ``POST``.
- The dashboard never displays or transmits password values.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets as _secrets
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse

from rekey.ports.event_bus import EventBus
from rekey.ports.handoff import HandoffDecision, HandoffOutcome

logger = logging.getLogger(__name__)


@dataclass
class PendingHandoff:
    """An in-flight approval prompt awaiting user input."""

    handoff_id: str
    attempt_id: str
    site: str
    prompt: str
    action_required: str
    future: asyncio.Future[HandoffDecision]


class WebDashboard:
    """FastAPI app + :class:`HandoffUI` implementation in one object.

    Construct once per CLI invocation. The same instance is wired in:
      - to the :class:`RotationService` (via composition root) as event_bus
        publisher — though publishing is done by the service; the dashboard
        only subscribes for SSE.
      - to the :class:`BrowserUseRotationDriver` as the ``handoff`` arg.
    """

    def __init__(
        self,
        *,
        event_bus: EventBus,
        host: str = "127.0.0.1",
        port: int = 7777,
    ) -> None:
        self._event_bus = event_bus
        self._host = host
        self._port = port
        self._pending: dict[str, PendingHandoff] = {}
        self._csrf_token = _secrets.token_urlsafe(32)
        self._app = self._build_app()

    @property
    def app(self) -> FastAPI:
        return self._app

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._port}"

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    # ---- HandoffUI implementation ----

    async def request_approval(
        self,
        *,
        attempt_id: str,
        site: str,
        prompt: str,
        action_required: str,
    ) -> HandoffDecision:
        loop = asyncio.get_event_loop()
        future: asyncio.Future[HandoffDecision] = loop.create_future()
        handoff = PendingHandoff(
            handoff_id=_secrets.token_urlsafe(8),
            attempt_id=attempt_id,
            site=site,
            prompt=prompt,
            action_required=action_required,
            future=future,
        )
        self._pending[handoff.handoff_id] = handoff
        logger.info(
            "Handoff requested: id=%s site=%s prompt=%s",
            handoff.handoff_id, site, prompt,
        )
        try:
            return await future
        finally:
            self._pending.pop(handoff.handoff_id, None)

    async def announce(self, attempt_id: str, message: str) -> None:
        # Status announcements travel via the EventBus / SSE stream already.
        return None

    # ---- FastAPI app ----

    def _build_app(self) -> FastAPI:
        app = FastAPI(title="rekey")

        @app.get("/", response_class=HTMLResponse)
        async def index() -> Response:
            response = HTMLResponse(content=_INDEX_HTML)
            # Issue CSRF cookie on first GET — it's regenerated per dashboard
            # instance and bound to that process.
            response.set_cookie(
                key="rekey_csrf",
                value=self._csrf_token,
                httponly=True,
                samesite="strict",
            )
            return response

        @app.get("/api/pending")
        async def list_pending() -> dict[str, list[dict[str, str]]]:
            return {
                "pending": [
                    {
                        "handoff_id": h.handoff_id,
                        "attempt_id": h.attempt_id,
                        "site": h.site,
                        "prompt": h.prompt,
                        "action_required": h.action_required,
                    }
                    for h in self._pending.values()
                ]
            }

        @app.get("/api/events")
        async def events() -> EventSourceResponse:
            async def stream():
                async for event in self._event_bus.subscribe():
                    yield {
                        "event": "rotation",
                        "data": json.dumps(
                            {
                                "attempt_id": event.attempt_id,
                                "state": event.state.value,
                                "timestamp": event.timestamp.isoformat(),
                                "message": event.message,
                                "data": event.data,
                            }
                        ),
                    }

            return EventSourceResponse(stream())

        @app.post("/api/handoff/{handoff_id}/resolve")
        async def resolve(handoff_id: str, request: Request) -> dict[str, bool]:
            self._verify_csrf(request)
            body = await request.json()
            outcome_str = body.get("outcome", "")
            note = body.get("note")
            try:
                outcome = HandoffOutcome(outcome_str)
            except ValueError as e:
                raise HTTPException(400, f"invalid outcome {outcome_str!r}") from e

            handoff = self._pending.get(handoff_id)
            if handoff is None:
                raise HTTPException(404, "unknown handoff")

            decision = HandoffDecision(outcome=outcome, note=note)
            if not handoff.future.done():
                handoff.future.set_result(decision)
            return {"ok": True}

        return app

    def _verify_csrf(self, request: Request) -> None:
        cookie = request.cookies.get("rekey_csrf")
        if cookie != self._csrf_token:
            raise HTTPException(403, "CSRF token mismatch — open the dashboard at / first")

    # ---- Server lifecycle ----

    async def serve(self) -> None:
        """Run the server until cancelled."""
        import uvicorn

        config = uvicorn.Config(
            self._app,
            host=self._host,
            port=self._port,
            log_level="warning",   # quiet by default; events flow via SSE
        )
        server = uvicorn.Server(config)
        await server.serve()


_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>rekey</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
           max-width: 860px; margin: 2rem auto; padding: 0 1rem; color: #1f2937; }
    h1 { margin-bottom: 0.25rem; }
    .subtitle { color: #6b7280; margin-bottom: 1.5rem; }
    .pending { border: 2px solid #f59e0b; background: #fffbeb;
               padding: 1rem 1.25rem; margin: 1rem 0; border-radius: 0.5rem; }
    .pending h3 { margin: 0 0 0.5rem 0; }
    .pending .what { color: #4b5563; margin: 0.5rem 0 1rem 0; }
    .events { max-height: 60vh; overflow-y: auto; border: 1px solid #e5e7eb;
              border-radius: 0.5rem; padding: 0.5rem; background: #f9fafb; }
    .event { padding: 0.4rem 0.75rem; border-left: 3px solid #cbd5e1;
             margin: 0.2rem 0; font-family: ui-monospace, monospace; font-size: 0.85rem; }
    .event.done, .event.writing_to_vault { border-color: #10b981; }
    .event.failed, .event.lockout_detected { border-color: #ef4444; }
    .event.awaiting_human_approval { border-color: #f59e0b; }
    button { padding: 0.55rem 1rem; margin-right: 0.5rem; cursor: pointer;
             border: 1px solid #cbd5e1; background: white; border-radius: 0.375rem;
             font-size: 0.95rem; }
    button:hover { background: #f3f4f6; }
    button.primary { background: #2563eb; color: white; border-color: #2563eb; }
    button.primary:hover { background: #1d4ed8; }
    button.danger { background: #dc2626; color: white; border-color: #dc2626; }
    .empty { color: #9ca3af; font-style: italic; padding: 1rem 0; }
  </style>
</head>
<body>
  <h1>rekey</h1>
  <p class="subtitle">Local credential hygiene agent — listening on this machine only.</p>

  <h2>Pending</h2>
  <div id="pending"></div>

  <h2>Event log</h2>
  <div class="events" id="events"></div>

  <script>
    const $pending = document.getElementById('pending');
    const $events = document.getElementById('events');
    const esc = s => String(s).replace(/[&<>"]/g, c => (
      {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]
    ));

    async function loadPending() {
      try {
        const r = await fetch('/api/pending', {credentials: 'include'});
        const {pending} = await r.json();
        if (pending.length === 0) {
          $pending.innerHTML = '<div class="empty">No pending hand-offs.</div>';
          return;
        }
        $pending.innerHTML = pending.map(p => `
          <div class="pending">
            <h3>${esc(p.site)} — needs your input</h3>
            <p><strong>${esc(p.prompt)}</strong></p>
            <p class="what">${esc(p.action_required)}</p>
            <button class="primary" data-id="${p.handoff_id}" data-outcome="approved">Approve</button>
            <button data-id="${p.handoff_id}" data-outcome="skipped">Skip site</button>
            <button class="danger" data-id="${p.handoff_id}" data-outcome="aborted">Abort</button>
          </div>
        `).join('');
        $pending.querySelectorAll('button').forEach(btn => {
          btn.addEventListener('click', () => resolve(btn.dataset.id, btn.dataset.outcome));
        });
      } catch (e) { /* silently retry on next tick */ }
    }

    async function resolve(handoff_id, outcome) {
      await fetch(`/api/handoff/${handoff_id}/resolve`, {
        method: 'POST', credentials: 'include',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({outcome}),
      });
      loadPending();
    }

    function streamEvents() {
      const es = new EventSource('/api/events');
      es.addEventListener('rotation', e => {
        const ev = JSON.parse(e.data);
        const div = document.createElement('div');
        div.className = 'event ' + ev.state;
        div.textContent = `[${new Date(ev.timestamp).toLocaleTimeString()}] ${ev.state}: ${ev.message}`;
        $events.insertBefore(div, $events.firstChild);
        loadPending();   // may reveal a new pending handoff
      });
    }

    loadPending();
    setInterval(loadPending, 3000);
    streamEvents();
  </script>
</body>
</html>"""
