"""First-run wizard, sign-in, and sign-out."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from gilgamesh.web.auth import AuthService, PasswordPolicyError, Session
from gilgamesh.web.deps import (
    SESSION_COOKIE,
    Redirect,
    current_session,
    read_form,
    require_session,
    set_session_cookie,
    templates,
    verify_csrf,
)

router = APIRouter()


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(
    request: Request, session: Annotated[Session | None, Depends(current_session)]
) -> Response:
    """First-run wizard. Closed once an administrator exists."""
    auth: AuthService = request.app.state.auth
    if session is not None or not auth.needs_setup():
        raise Redirect("/")
    return templates.TemplateResponse(request=request, name="setup.html", context={})


@router.post("/setup")
async def setup_submit(
    request: Request,
    session: Annotated[Session | None, Depends(current_session)],
) -> Response:
    """Create the first administrator and sign in.

    The setup token from the journal is required: until the owner has claimed the box,
    anyone who can reach the port could otherwise become the administrator.
    """
    auth: AuthService = request.app.state.auth
    if session is not None or not auth.needs_setup():
        raise Redirect("/")
    form = await read_form(request)
    if not auth.verify_setup_token(form.get("setup_token", "")):
        return templates.TemplateResponse(
            request=request,
            name="setup.html",
            context={
                "error": (
                    "Setup token is missing or wrong. It is printed in the service log: "
                    "journalctl -u gilgamesh-web | grep setup"
                )
            },
            status_code=400,
        )
    try:
        user = auth.create_user(form.get("username", "").strip(), form.get("password", ""))
    except (PasswordPolicyError, ValueError) as exc:
        return templates.TemplateResponse(
            request=request, name="setup.html", context={"error": str(exc)}, status_code=400
        )
    auth.clear_setup_token()
    new_session = auth.start_session(user)
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(response, new_session.sid, request)
    return response


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request, session: Annotated[Session | None, Depends(current_session)]
) -> Response:
    """Sign-in page."""
    if session is not None:
        raise Redirect("/")
    return templates.TemplateResponse(request=request, name="login.html", context={})


@router.post("/login")
async def login_submit(
    request: Request,
    session: Annotated[Session | None, Depends(current_session)],
) -> Response:
    """Authenticate and start a session."""
    if session is not None:
        raise Redirect("/")
    auth: AuthService = request.app.state.auth
    form = await read_form(request)
    client = request.client.host if request.client else None
    new_session = auth.login(form.get("username", "").strip(), form.get("password", ""), client)
    if new_session is None:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Incorrect username or password."},
            status_code=401,
        )
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(response, new_session.sid, request)
    return response


@router.post("/logout", dependencies=[Depends(verify_csrf)])
async def logout(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Destroy the session and clear its cookie."""
    auth: AuthService = request.app.state.auth
    auth.revoke_session(session.sid)
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
