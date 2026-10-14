"""FastAPI application factory, authentication wiring, and routes.

**Dependencies live at module scope on purpose.** With ``from __future__ import
annotations`` (PEP 563), FastAPI re-evaluates annotations as strings in the *module*
namespace. A dependency defined inside ``create_app`` is a closure local, so
``Depends(current_session)`` cannot be resolved there and silently degrades into an
ordinary query parameter — which fails as a confusing 422, not as an import error.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.rules import (
    RuleConfigService,
    RuleParamError,
    SuppressionField,
    default_catalogue,
)
from gilgamesh.sensors.fake import FakeDetector
from gilgamesh.web.auth import AuthService, PasswordPolicyError, Session, create_auth_service

TEMPLATES_DIR = Path(__file__).parent / "templates"
SESSION_COOKIE = "gilgamesh_session"
#: Matches the absolute session timeout so cookie and server-side row expire together.
SESSION_COOKIE_MAX_AGE = 12 * 3600

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_URLENCODED = "application/x-www-form-urlencoded"

templates = Jinja2Templates(directory=TEMPLATES_DIR)


class _Redirect(Exception):
    """Signalled by a route that wants to send the browser elsewhere."""

    def __init__(self, location: str) -> None:
        super().__init__(location)
        self.location = location


async def read_form(request: Request) -> dict[str, str]:
    """Parse a URL-encoded form body.

    FastAPI's ``Form()`` and Starlette's ``request.form()`` both require
    ``python-multipart`` (``Apache-2.0``) in Starlette 1.8 — *even for URL-encoded
    bodies* — which decision D-020 excludes on licence grounds. Gilgamesh has no file
    uploads and both HTML forms and htmx post URL-encoded by default, so parsing the
    body here keeps the dependency out of the tree. Anything else is refused rather
    than silently mis-parsed. (Decision D-030.)
    """
    content_type = request.headers.get("content-type", "")
    if content_type and not content_type.startswith(_URLENCODED):
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            f"only {_URLENCODED} bodies are accepted",
        )
    body = (await request.body()).decode("utf-8", "replace")
    return {key: values[0] for key, values in parse_qs(body, keep_blank_values=True).items()}


def current_session(request: Request) -> Session | None:
    """The session for this request, or ``None`` if the visitor is anonymous."""
    auth: AuthService = request.app.state.auth
    sid = request.cookies.get(SESSION_COOKIE)
    return auth.validate_session(sid) if sid else None


def require_session(request: Request) -> Session:
    """The session, or a redirect to the wizard/login page."""
    session = current_session(request)
    if session is not None:
        return session
    auth: AuthService = request.app.state.auth
    raise _Redirect("/setup" if auth.needs_setup() else "/login")


async def verify_csrf(
    request: Request,
    session: Annotated[Session, Depends(require_session)],
) -> None:
    """Reject unsafe requests that do not carry the session's CSRF token.

    Registered as a dependency on every state-changing route, so a new route is
    protected by construction rather than by remembering.
    """
    if request.method not in _UNSAFE_METHODS:
        return
    supplied = request.headers.get("X-CSRF-Token")
    if supplied is None and request.method == "POST":
        supplied = (await read_form(request)).get("csrf_token") or None
    auth: AuthService = request.app.state.auth
    if not auth.check_csrf(session, supplied):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")


def _set_session_cookie(response: Response, sid: str, request: Request) -> None:
    """Attach the session cookie with the flags that matter for a security tool.

    ``HttpOnly`` keeps it away from JavaScript, ``SameSite=Lax`` blunts cross-site
    submission, and ``Secure`` is set whenever the request arrived over TLS.
    """
    response.set_cookie(
        SESSION_COOKIE,
        sid,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
        max_age=SESSION_COOKIE_MAX_AGE,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the Gilgamesh web application.

    Uses the current FastAPI ``lifespan`` API (recommended over the deprecated
    ``@app.on_event``) to open the database on startup and close it on shutdown.
    """
    resolved = settings if settings is not None else Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        database = Database(resolved.db_path)
        database.initialize()
        app.state.settings = resolved
        app.state.db = database
        app.state.auth = create_auth_service(database)
        app.state.rules = RuleConfigService(database, default_catalogue())
        # The walking skeleton (milestone M1) proves the pipeline with the fake
        # detector; the real sensor process replaces this in milestone M8.
        for event in FakeDetector().events():
            database.insert_event(event)
        try:
            yield
        finally:
            database.close()

    app = FastAPI(title="Gilgamesh", lifespan=lifespan)

    @app.exception_handler(_Redirect)
    async def _redirect_handler(request: Request, exc: _Redirect) -> Response:
        return RedirectResponse(exc.location, status_code=status.HTTP_303_SEE_OTHER)

    # --- public ------------------------------------------------------------

    @app.get("/api/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness probe. Unauthenticated on purpose: it reveals nothing."""
        return {"status": "ok"}

    @app.get("/setup", response_class=HTMLResponse)
    async def setup_page(
        request: Request, session: Annotated[Session | None, Depends(current_session)]
    ) -> Response:
        """First-run wizard. Closed once an administrator exists."""
        auth: AuthService = request.app.state.auth
        if session is not None or not auth.needs_setup():
            raise _Redirect("/")
        return templates.TemplateResponse(request=request, name="setup.html", context={})

    @app.post("/setup")
    async def setup_submit(
        request: Request,
        session: Annotated[Session | None, Depends(current_session)],
    ) -> Response:
        """Create the first administrator and sign in."""
        auth: AuthService = request.app.state.auth
        if session is not None or not auth.needs_setup():
            raise _Redirect("/")
        form = await read_form(request)
        try:
            user = auth.create_user(form.get("username", "").strip(), form.get("password", ""))
        except (PasswordPolicyError, ValueError) as exc:
            return templates.TemplateResponse(
                request=request, name="setup.html", context={"error": str(exc)}, status_code=400
            )
        new_session = auth.start_session(user)
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        _set_session_cookie(response, new_session.sid, request)
        return response

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(
        request: Request, session: Annotated[Session | None, Depends(current_session)]
    ) -> Response:
        """Sign-in page."""
        if session is not None:
            raise _Redirect("/")
        return templates.TemplateResponse(request=request, name="login.html", context={})

    @app.post("/login")
    async def login_submit(
        request: Request,
        session: Annotated[Session | None, Depends(current_session)],
    ) -> Response:
        """Authenticate and start a session."""
        if session is not None:
            raise _Redirect("/")
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
        _set_session_cookie(response, new_session.sid, request)
        return response

    @app.post("/logout")
    async def logout(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> Response:
        """Destroy the session and clear its cookie."""
        auth: AuthService = request.app.state.auth
        auth.revoke_session(session.sid)
        response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # --- authenticated -----------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> Response:
        """Render the live dashboard."""
        database: Database = request.app.state.db
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={"events": database.list_events(), "session": session, "settings": resolved},
        )

    @app.get("/api/events")
    async def list_events(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> list[dict[str, object]]:
        """Return the most recent events, newest first."""
        database: Database = request.app.state.db
        return [event.model_dump(mode="json") for event in database.list_events()]

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> Response:
        """Application settings."""
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={"session": session, "retention_days": 30},
        )

    @app.post("/settings", dependencies=[Depends(verify_csrf)])
    async def settings_save(
        request: Request,
        session: Annotated[Session, Depends(require_session)],
    ) -> Response:
        """Save settings. Protected by the CSRF dependency."""
        form = await read_form(request)
        raw = form.get("retention_days", "30")
        try:
            retention_days = int(raw)
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "retention_days must be a whole number"
            ) from exc
        if not 1 <= retention_days <= 365:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "retention_days must be between 1 and 365",
            )
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={"session": session, "retention_days": retention_days, "saved": True},
        )

    # --- detection rules and allowlists -----------------------------------

    @app.get("/rules", response_class=HTMLResponse)
    async def rules_page(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> Response:
        """Detection rules: toggle each built-in rule and set its typed parameters."""
        return _rules_page(request, session)

    @app.post("/rules/toggle", dependencies=[Depends(verify_csrf)])
    async def rules_toggle(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> Response:
        """Enable or disable one rule."""
        service: RuleConfigService = request.app.state.rules
        form = await read_form(request)
        rule_id = form.get("rule_id", "")
        enabled = form.get("enabled", "1") in {"1", "true", "yes", "on"}
        try:
            service.set_enabled(rule_id, enabled)
        except RuleParamError as exc:
            return _rules_page(request, session, notice=f"Not saved: {exc}")
        state = "enabled" if enabled else "disabled"
        return _rules_page(request, session, notice=f"{rule_id} {state}.")

    @app.post("/rules/params", dependencies=[Depends(verify_csrf)])
    async def rules_params(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> Response:
        """Save typed parameters for one rule."""
        service: RuleConfigService = request.app.state.rules
        form = await read_form(request)
        rule_id = form.get("rule_id", "")
        # Every parameter belonging to this rule is submitted together; anything else
        # in the form is ignored by the validator rather than trusted.
        submitted = {key: value for key, value in form.items() if key != "rule_id"}
        submitted.pop("csrf_token", None)
        try:
            service.set_params(rule_id, submitted)
        except RuleParamError as exc:
            return _rules_page(request, session, notice=f"Not saved: {exc}")
        return _rules_page(request, session, notice=f"Saved {rule_id}.")

    @app.get("/suppressions", response_class=HTMLResponse)
    async def suppressions_page(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> Response:
        """The allowlist: sources whose events are ignored."""
        return _suppressions_page(request, session)

    @app.post("/suppressions", dependencies=[Depends(verify_csrf)])
    async def suppressions_add(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> Response:
        """Add an allowlist entry."""
        service: RuleConfigService = request.app.state.rules
        form = await read_form(request)
        try:
            field_name = SuppressionField(form.get("field", "").strip())
        except ValueError:
            return _suppressions_page(request, session, error="Choose what to match on.")
        try:
            service.add_suppression(
                form.get("rule_id", ""),
                field_name,
                form.get("value", ""),
                form.get("note", ""),
            )
        except RuleParamError as exc:
            return _suppressions_page(request, session, error=f"Not saved: {exc}")
        return _suppressions_page(request, session, notice="Allowlist entry added.")

    @app.post("/suppressions/delete", dependencies=[Depends(verify_csrf)])
    async def suppressions_delete(
        request: Request, session: Annotated[Session, Depends(require_session)]
    ) -> Response:
        """Remove an allowlist entry."""
        service: RuleConfigService = request.app.state.rules
        form = await read_form(request)
        try:
            service.remove_suppression(int(form.get("id", "0")))
        except (RuleParamError, ValueError) as exc:
            return _suppressions_page(request, session, error=f"Not removed: {exc}")
        return _suppressions_page(request, session, notice="Allowlist entry removed.")

    return app


def _rules_page(request: Request, session: Session, notice: str = "") -> Response:
    """Render the detection rules page."""
    service: RuleConfigService = request.app.state.rules
    settings = service.settings()
    return templates.TemplateResponse(
        request=request,
        name="rules.html",
        context={
            "session": session,
            "rules": [
                {"definition": definition, "setting": settings[definition.id]}
                for definition in service.catalogue.definitions()
            ],
            "notice": notice,
        },
    )


def _suppressions_page(
    request: Request, session: Session, notice: str = "", error: str = ""
) -> Response:
    """Render the allowlist page."""
    service: RuleConfigService = request.app.state.rules
    return templates.TemplateResponse(
        request=request,
        name="suppressions.html",
        context={
            "session": session,
            "catalogue": service.catalogue,
            "suppressions": service.suppressions(),
            "notice": notice,
            "error": error,
        },
    )
