"""Application settings: retention, network intent, account, and HTTPS display."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

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
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Application settings."""
    return _settings_page(request, session)


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
            return _settings_page(
                request, session, error="Retention must be a whole number of days."
            )
    for key in ("network_mode", "lan_interface", "wan_interface", "https_mode"):
        if key in form:
            updates[key] = form[key].strip()
    try:
        store.update(**updates)
    except PreferenceError as exc:
        return _settings_page(request, session, error=f"Not saved: {exc}")
    return _settings_page(request, session, notice="Settings saved.")


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
        return _settings_page(request, session, error=f"Password not changed: {exc}")
    new_session = auth.start_session(user)
    response = RedirectResponse("/settings", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(response, new_session.sid, request)
    return response


def _settings_page(
    request: Request, session: Session, *, notice: str = "", error: str = ""
) -> Response:
    """Render the settings form with the stored preferences."""
    store = PreferencesStore(request.app.state.db)
    prefs = store.get()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "session": session,
            "prefs": prefs,
            "settings": request.app.state.settings,
            "notice": notice,
            "error": error,
        },
    )
