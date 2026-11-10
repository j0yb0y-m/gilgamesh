"""Application settings: retention, network intent, account, and HTTPS display."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from gilgamesh.ai.context import (
    ContextTooLarge,
    RedactionSettings,
    build_explanation_context,
    render_context,
)
from gilgamesh.ai.secrets import AiKeyStore
from gilgamesh.ai.settings import PRESETS, AiSettings
from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.preferences import PreferenceError, PreferencesStore
from gilgamesh.web.auth import AuthService, PasswordPolicyError, Session
from gilgamesh.web.deps import (
    read_form,
    require_session,
    set_session_cookie,
    templates,
    verify_csrf,
)

router = APIRouter()


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    session: Annotated[Session, Depends(require_session)],
    saved: str = "",
) -> Response:
    """Application settings."""
    notices = {
        "behaviour": "Behaviour detection saved.",
        "ai": "AI settings saved.",
        "ai_key_cleared": "AI API key cleared.",
    }
    return render_settings_page(request, session, notice=notices.get(saved, ""))


@router.post("/settings", dependencies=[Depends(verify_csrf)])
async def settings_save(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Save the owner's preferences. Protected by the CSRF dependency."""
    store = PreferencesStore(request.app.state.db)
    form = await read_form(request)
    updates: dict[str, object] = {}
    if "retention_days" in form:
        try:
            updates["retention_days"] = int(form["retention_days"])
        except ValueError:
            return render_settings_page(
                request, session, error="Retention must be a whole number of days."
            )
    for key in ("network_mode", "lan_interface", "wan_interface", "https_mode"):
        if key in form:
            updates[key] = form[key].strip()
    try:
        store.update(**updates)
    except PreferenceError as exc:
        return render_settings_page(request, session, error=f"Not saved: {exc}")
    return render_settings_page(request, session, notice="Settings saved.")


@router.post("/settings/behaviour", dependencies=[Depends(verify_csrf)])
async def behaviour_save(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Save the behaviour toggle and calibration window."""
    store = PreferencesStore(request.app.state.db)
    current = store.get()
    form = await read_form(request)
    enabled = form.get("behaviour_enabled", "0") in {"1", "true", "yes", "on"}
    try:
        calibration_days = int(
            form.get("behaviour_calibration_days", str(current.behaviour_calibration_days))
        )
    except ValueError:
        return render_settings_page(
            request,
            session,
            error="Not saved: calibration must be a whole number of days.",
        )
    try:
        updated = store.update(
            behaviour_enabled=enabled,
            behaviour_calibration_days=calibration_days,
        )
    except PreferenceError as exc:
        return render_settings_page(request, session, error=f"Not saved: {exc}")
    request.app.state.db.insert_audit_entry(
        "behaviour detection "
        f"{'enabled' if updated.behaviour_enabled else 'disabled'} "
        f"with {updated.behaviour_calibration_days}-day calibration "
        f"by {session.user.username}"
    )
    return RedirectResponse("/settings?saved=behaviour", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/settings/password", dependencies=[Depends(verify_csrf)])
async def settings_change_password(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Change the administrator password and re-issue this browser's session."""
    auth: AuthService = request.app.state.auth
    form = await read_form(request)
    try:
        user = auth.change_password(
            session.user.username,
            form.get("current_password", ""),
            form.get("new_password", ""),
        )
    except PasswordPolicyError as exc:
        return render_settings_page(request, session, error=f"Password not changed: {exc}")
    new_session = auth.start_session(user)
    response = RedirectResponse("/settings", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(response, new_session.sid, request)
    return response


def render_settings_page(
    request: Request,
    session: Session,
    *,
    notice: str = "",
    error: str = "",
    ai: AiSettings | None = None,
) -> Response:
    """Render the settings form with the stored preferences and AI card state."""
    store = PreferencesStore(request.app.state.db)
    prefs = store.get()
    keys: AiKeyStore = request.app.state.ai_keys
    ai_settings = ai if ai is not None else request.app.state.ai_settings.get()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "session": session,
            "prefs": prefs,
            "settings": request.app.state.settings,
            "ai": ai_settings,
            "ai_key_set": keys.is_set(),
            "ai_key_available": keys.get_key() is not None,
            "presets": PRESETS,
            "preview": _preview(request, ai_settings),
            "notice": notice,
            "error": error,
        },
    )


def _preview(request: Request, ai: AiSettings) -> dict[str, str | bool | None]:
    """Render the redacted context the AI would receive, plus a sample.

    The owner can see exactly what leaves the box before enabling anything. The
    sample proves the shape of a behaviour alert; the latest stored event proves
    what the current redaction settings do to real data.
    """
    database: Database = request.app.state.db
    redaction = RedactionSettings(
        redact_mac=ai.redact_mac,
        redact_hostname=ai.redact_hostname,
        redact_ips=ai.redact_ips,
    )
    latest = database.list_events(limit=1)
    return {
        "sample_json": _render_preview(_sample_event(), redaction),
        "latest_json": _render_preview(latest[0], redaction) if latest else None,
        "has_latest": bool(latest),
    }


def _sample_event() -> Event:
    """A representative behaviour alert, with identifiers for the redactor to hide."""
    return Event(
        type=EventType.BEHAVIOUR_ANOMALY,
        severity=Severity.MEDIUM,
        detector="behaviour.volume_spike",
        summary="A device uploaded far more data than its baseline",
        src_mac="aa:bb:cc:dd:ee:01",
        src_ip="10.0.0.20",
        details={
            "signal": "volume_spike",
            "direction": "out",
            "observed_bytes": 1_800_000_000,
            "baseline_mean_bytes": 4_200_000,
            "ratio": 428.6,
            "z_score": 9.1,
            "consecutive_buckets": 1,
            "window_end": "2026-11-10T11:45:00+00:00",
        },
    )


def _render_preview(event: Event, redaction: RedactionSettings) -> str | None:
    """Render one event's context, or ``None`` when it cannot be sent safely."""
    try:
        context = build_explanation_context(
            event,
            incident_row=None,
            related_events=[],
            behaviour_profile=None,
            redaction=redaction,
        )
        return render_context(context)
    except ContextTooLarge:
        return None
