"""The live dashboard, its event stream, and the JSON/health endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.sse import EventSourceResponse

from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.web.auth import Session
from gilgamesh.web.deps import require_session, templates
from gilgamesh.web.sse import EventBus

router = APIRouter()


@router.get("/api/healthz")
async def healthz() -> dict[str, str]:
    """Liveness probe. Unauthenticated on purpose: it reveals nothing."""
    return {"status": "ok"}


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Render the live dashboard."""
    database: Database = request.app.state.db
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "events": database.list_events(),
            "session": session,
            "settings": request.app.state.settings,
            "stats": _dashboard_stats(request),
        },
    )


@router.get("/events/stream")
async def event_stream(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> EventSourceResponse:
    """Stream new alerts to the dashboard over server-sent events."""
    bus: EventBus = request.app.state.bus
    del session  # authenticated above; the session is not sent to the browser
    # `no-cache` is part of the SSE contract: without it a proxy (or the browser's
    # own cache) is free to hold frames back, and the dashboard silently stops being
    # live. `X-Accel-Buffering: no` asks nginx-likes to do the same.
    return EventSourceResponse(
        bus.subscribe(),
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/api/events")
async def list_events(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> list[dict[str, object]]:
    """Return the most recent events, newest first."""
    database: Database = request.app.state.db
    return [event.model_dump(mode="json") for event in database.list_events()]


def _dashboard_stats(request: Request) -> dict[str, int]:
    """The tiles at the top of the dashboard: counts the owner wants at a glance."""
    database: Database = request.app.state.db
    start_of_day = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    today = database.query(
        "SELECT COUNT(*) AS n FROM events WHERE ts >= ?", (start_of_day.isoformat(),)
    )
    total = database.query("SELECT COUNT(*) AS n FROM events")
    devices: DeviceStore = request.app.state.devices
    return {
        "events_today": int(today[0]["n"]) if today else 0,
        "events_total": int(total[0]["n"]) if total else 0,
        "devices": len(devices.list()),
    }
