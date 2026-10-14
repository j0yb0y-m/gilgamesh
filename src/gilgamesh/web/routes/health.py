"""The Health page: system metrics and the "update rules" action."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response

from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.health import HealthReport, collect_health
from gilgamesh.preferences import PreferencesStore
from gilgamesh.rules_update import RulesUpdateResult, read_rules_version
from gilgamesh.web.auth import Session
from gilgamesh.web.deps import require_session, templates, verify_csrf

router = APIRouter()


@router.get("/health", response_class=HTMLResponse)
async def health_page(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Show how the box itself is doing, and how fresh the rules are."""
    return _health_page(request, session)


@router.post("/health/rules/update", dependencies=[Depends(verify_csrf)])
async def rules_update(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Run the same rules update the systemd timer runs, in the background thread."""
    updater = request.app.state.rules_update
    result: RulesUpdateResult = await run_in_threadpool(updater)
    notice = "Rules updated: " + "; ".join(result.steps) if result.ok else ""
    error = "" if result.ok else f"Rules update failed: {result.error}"
    return _health_page(request, session, notice=notice, error=error, steps=result.steps)


def _health_page(
    request: Request,
    session: Session,
    *,
    notice: str = "",
    error: str = "",
    steps: tuple[str, ...] = (),
) -> Response:
    """Render the health report plus the rule-update controls."""
    settings: Settings = request.app.state.settings
    prefs = PreferencesStore(request.app.state.db).get()
    report = collect_health(
        data_dir=settings.data_dir,
        interfaces=(prefs.lan_interface, prefs.wan_interface),
    )
    report = report.with_context(
        last_event_ts=_last_event_ts(request.app.state.db),
        rule_version=read_rules_version(settings),
    )
    return templates.TemplateResponse(
        request=request,
        name="health.html",
        context={
            "session": session,
            "report": _report_for_template(report),
            "notice": notice,
            "error": error,
            "steps": steps,
        },
    )


def _last_event_ts(database: Database) -> datetime | None:
    rows = database.query("SELECT ts FROM events ORDER BY ts DESC LIMIT 1")
    if not rows:
        return None
    try:
        return datetime.fromisoformat(rows[0]["ts"])
    except ValueError:
        return None


def _report_for_template(report: HealthReport) -> dict[str, object]:
    """Flatten the report into values the template can print without formatting logic."""
    return {
        "load": (report.load_1m, report.load_5m, report.load_15m),
        "cpu_count": report.cpu_count,
        "cpu_temp_c": report.cpu_temp_c,
        "uptime_seconds": report.uptime_seconds,
        "memory_total_kb": report.memory_total_kb,
        "memory_available_kb": report.memory_available_kb,
        "memory_used_percent": report.memory_used_percent,
        "disk_total_bytes": report.disk_total_bytes,
        "disk_free_bytes": report.disk_free_bytes,
        "disk_used_percent": report.disk_used_percent,
        "interfaces": report.interfaces,
        "last_event_ts": report.last_event_ts,
        "rule_version": report.rule_version,
    }
