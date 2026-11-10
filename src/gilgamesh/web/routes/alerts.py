"""The alert list, one alert's detail page, and acknowledging / dismissing."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from gilgamesh.ai.service import ExplanationService
from gilgamesh.db import Database
from gilgamesh.models import EventType, Severity
from gilgamesh.web.auth import Session
from gilgamesh.web.deps import read_form, require_session, templates, verify_csrf

router = APIRouter()


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    session: Annotated[Session, Depends(require_session)],
    severity: str = "",
    event_type: str = "",
    search: str = "",
) -> Response:
    """The alert list, filterable by severity and type."""
    database: Database = request.app.state.db
    events = database.list_events(limit=200)
    if severity:
        events = [e for e in events if str(e.severity) == severity]
    if event_type:
        events = [e for e in events if str(e.type) == event_type]
    if search:
        needle = search.lower()
        events = [e for e in events if needle in e.summary.lower()]
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "session": session,
            "events": events,
            "severity": severity,
            "event_type": event_type,
            "search": search,
            "severities": [s.value for s in Severity],
            "event_types": [t.value for t in EventType],
        },
    )


@router.get("/alerts/{event_id}", response_class=HTMLResponse)
async def alert_detail(
    request: Request,
    event_id: str,
    session: Annotated[Session, Depends(require_session)],
) -> Response:
    """One alert with its full evidence."""
    database: Database = request.app.state.db
    event = database.get_event(event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such alert")
    return templates.TemplateResponse(
        request=request,
        name="alert_detail.html",
        context={"session": session, "event": event, "details": event.details},
    )


@router.post("/alerts/{event_id}/acknowledge", dependencies=[Depends(verify_csrf)])
async def alert_acknowledge(
    request: Request,
    event_id: str,
    session: Annotated[Session, Depends(require_session)],
) -> RedirectResponse:
    """Mark an alert as seen by the owner."""
    database: Database = request.app.state.db
    if database.get_event(event_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such alert")
    database.insert_audit_entry(f"alert {event_id} acknowledged by {session.user.username}")
    return RedirectResponse("/alerts", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/alerts/{event_id}/false-positive", dependencies=[Depends(verify_csrf)])
async def alert_false_positive(
    request: Request,
    event_id: str,
    session: Annotated[Session, Depends(require_session)],
) -> RedirectResponse:
    """Record that an alert was benign, so the owner's own triage is auditable."""
    database: Database = request.app.state.db
    if database.get_event(event_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such alert")
    form = await read_form(request)
    note = form.get("note", "").strip()
    entry = f"alert {event_id} marked false-positive by {session.user.username}"
    if note:
        entry = f"{entry}: {note}"
    database.insert_audit_entry(entry)
    return RedirectResponse(f"/alerts/{event_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/alerts/{event_id}/explain", dependencies=[Depends(verify_csrf)])
async def alert_explain(
    request: Request,
    event_id: str,
    session: Annotated[Session, Depends(require_session)],
) -> Response:
    """Explain one alert with the provider when enabled, or the template."""
    return await _explain(request, event_id, session, regenerate=False)


@router.post("/alerts/{event_id}/explain/regenerate", dependencies=[Depends(verify_csrf)])
async def alert_explain_regenerate(
    request: Request,
    event_id: str,
    session: Annotated[Session, Depends(require_session)],
) -> Response:
    """Force a fresh provider call, replacing the cached explanation."""
    return await _explain(request, event_id, session, regenerate=True)


async def _explain(
    request: Request,
    event_id: str,
    session: Session,
    *,
    regenerate: bool,
) -> Response:
    """Shared body of the Explain and Regenerate routes.

    Both return only the partial, so htmx can swap it into ``#explanation``
    without reloading the evidence above it.
    """
    database: Database = request.app.state.db
    event = database.get_event(event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such alert")
    service: ExplanationService = request.app.state.explanations
    outcome = await service.explain(event, regenerate=regenerate)
    return templates.TemplateResponse(
        request=request,
        name="_explanation.html",
        context={"session": session, "event": event, "outcome": outcome},
    )
