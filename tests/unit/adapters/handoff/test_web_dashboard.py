"""Tests for the WebDashboard FastAPI app and HandoffUI implementation."""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from rekey.adapters.event_bus.in_memory import InMemoryEventBus
from rekey.adapters.handoff.web_dashboard import WebDashboard
from rekey.ports.handoff import HandoffOutcome


@pytest.fixture
def dashboard() -> WebDashboard:
    return WebDashboard(event_bus=InMemoryEventBus())


@pytest.fixture
async def client(dashboard: WebDashboard):
    transport = ASGITransport(app=dashboard.app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestIndexAndCSRF:
    async def test_index_returns_html(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "rekey" in resp.text

    async def test_index_issues_csrf_cookie(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        assert resp.status_code == 200
        # CSRF cookie should be set
        set_cookie = resp.headers.get("set-cookie", "")
        assert "rekey_csrf" in set_cookie
        assert "httponly" in set_cookie.lower()


class TestPendingList:
    async def test_empty_initially(self, client: AsyncClient) -> None:
        resp = await client.get("/api/pending")
        assert resp.status_code == 200
        assert resp.json() == {"pending": []}

    async def test_lists_pending_after_request(
        self,
        dashboard: WebDashboard,
        client: AsyncClient,
    ) -> None:
        task = asyncio.create_task(
            dashboard.request_approval(
                attempt_id="a1",
                site="github.com",
                prompt="confirm",
                action_required="click approve",
            )
        )
        await asyncio.sleep(0.01)

        resp = await client.get("/api/pending")
        data = resp.json()
        assert len(data["pending"]) == 1
        assert data["pending"][0]["site"] == "github.com"
        assert data["pending"][0]["prompt"] == "confirm"

        # Resolve via dashboard directly so the consumer task ends
        handoff_id = data["pending"][0]["handoff_id"]
        dashboard._pending[handoff_id].future.set_result(
            type(await task)(outcome=HandoffOutcome.APPROVED)  # type: ignore[arg-type]
        ) if False else None  # see resolution test below
        if not task.done():
            # Cancel cleanup
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, BaseException):
                pass


class TestHandoffResolution:
    async def test_approve_resolves_future(
        self,
        dashboard: WebDashboard,
        client: AsyncClient,
    ) -> None:
        # Establish CSRF cookie first
        await client.get("/")

        # Start a pending handoff
        task = asyncio.create_task(
            dashboard.request_approval(
                attempt_id="a1",
                site="github.com",
                prompt="confirm",
                action_required="click approve",
            )
        )
        await asyncio.sleep(0.01)

        handoff_id = next(iter(dashboard._pending))
        resp = await client.post(
            f"/api/handoff/{handoff_id}/resolve",
            json={"outcome": "approved"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

        decision = await asyncio.wait_for(task, timeout=1.0)
        assert decision.outcome == HandoffOutcome.APPROVED
        assert handoff_id not in dashboard._pending  # cleaned up

    async def test_skip_outcome(
        self,
        dashboard: WebDashboard,
        client: AsyncClient,
    ) -> None:
        await client.get("/")
        task = asyncio.create_task(
            dashboard.request_approval(
                attempt_id="a1",
                site="example.com",
                prompt="x",
                action_required="y",
            )
        )
        await asyncio.sleep(0.01)

        handoff_id = next(iter(dashboard._pending))
        await client.post(
            f"/api/handoff/{handoff_id}/resolve",
            json={"outcome": "skipped"},
        )
        decision = await asyncio.wait_for(task, timeout=1.0)
        assert decision.outcome == HandoffOutcome.SKIPPED

    async def test_abort_outcome(
        self,
        dashboard: WebDashboard,
        client: AsyncClient,
    ) -> None:
        await client.get("/")
        task = asyncio.create_task(
            dashboard.request_approval(
                attempt_id="a1",
                site="example.com",
                prompt="x",
                action_required="y",
            )
        )
        await asyncio.sleep(0.01)

        handoff_id = next(iter(dashboard._pending))
        await client.post(
            f"/api/handoff/{handoff_id}/resolve",
            json={"outcome": "aborted"},
        )
        decision = await asyncio.wait_for(task, timeout=1.0)
        assert decision.outcome == HandoffOutcome.ABORTED


class TestCSRF:
    async def test_post_without_cookie_returns_403(self, client: AsyncClient) -> None:
        # Skip the GET /, so no CSRF cookie is set.
        resp = await client.post(
            "/api/handoff/some-id/resolve",
            json={"outcome": "approved"},
        )
        assert resp.status_code == 403

    async def test_post_with_wrong_cookie_returns_403(
        self,
        client: AsyncClient,
    ) -> None:
        await client.get("/")  # set valid cookie
        # Override with wrong value
        client.cookies.set("rekey_csrf", "wrong-token")
        resp = await client.post(
            "/api/handoff/some-id/resolve",
            json={"outcome": "approved"},
        )
        assert resp.status_code == 403


class TestErrors:
    async def test_unknown_handoff_id_returns_404(self, client: AsyncClient) -> None:
        await client.get("/")
        resp = await client.post(
            "/api/handoff/nonexistent/resolve",
            json={"outcome": "approved"},
        )
        assert resp.status_code == 404

    async def test_invalid_outcome_returns_400(
        self,
        dashboard: WebDashboard,
        client: AsyncClient,
    ) -> None:
        await client.get("/")
        task = asyncio.create_task(
            dashboard.request_approval(
                attempt_id="a1",
                site="x",
                prompt="x",
                action_required="x",
            )
        )
        await asyncio.sleep(0.01)
        handoff_id = next(iter(dashboard._pending))
        resp = await client.post(
            f"/api/handoff/{handoff_id}/resolve",
            json={"outcome": "totally-bogus"},
        )
        assert resp.status_code == 400
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, BaseException):
            pass
