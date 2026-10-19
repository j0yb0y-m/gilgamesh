"""Shared web dependencies: templates, session resolution, CSRF, cookies.

**These live at module scope on purpose.** With ``from __future__ import annotations``
(PEP 563), FastAPI re-evaluates a route's annotations as strings in the *module* where
the route is defined. A dependency must therefore be importable by name from that
module. Keeping every dependency here — imported into each ``gilgamesh.web.routes``
module — means a route can never accidentally reference a closure local, which FastAPI
silently degrades into a query parameter and reports as a puzzling ``422``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any
from urllib.parse import parse_qs

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates

from gilgamesh.web.auth import AuthService, Session

TEMPLATES_DIR = Path(__file__).parent / "templates"
#: Vendored CSS/JS. Kept at the repository root so the built assets are committed
#: alongside the templates that reference them (constraint C6: no Node on the Pi).
STATIC_DIR = Path(__file__).resolve().parents[3] / "static"
SESSION_COOKIE = "gilgamesh_session"
#: Matches the absolute session timeout so cookie and server-side row expire together.
SESSION_COOKIE_MAX_AGE = 12 * 3600

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_URLENCODED = "application/x-www-form-urlencoded"


def asset_version(directory: Path | None = None) -> str:
    """A short stamp that changes whenever a served asset changes.

    The vendored CSS/JS keep their file names across upgrades, so after ``install.sh``
    a browser can keep executing the *previous* ``app.js`` — the owner then sees the old
    behaviour with no clue why. Querying each asset by this stamp gives every asset a URL
    that changes exactly when its bytes do, which is the one cache-busting mechanism that
    does not depend on a browser's revalidation heuristics. The response also carries
    ``Cache-Control: no-cache`` (see
    :class:`~gilgamesh.web.middleware.SecurityHeadersMiddleware`), so an unchanged asset
    still costs only a ``304``.

    Computed once per process: assets change with a deployment, and a deployment restarts
    the service.
    """
    root = STATIC_DIR if directory is None else directory
    newest = 0.0
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_file():
            info = path.stat()
            newest = max(newest, info.st_mtime)
            total += info.st_size
    return f"{int(newest):x}.{total:x}"


#: The stamp every rendered page carries. See :func:`asset_version`.
ASSET_VERSION = asset_version()


def _asset_context(request: Request) -> dict[str, Any]:
    """Expose the asset stamp to every template (``?v={{ asset_version }}``)."""
    del request  # only here for the context-processor contract
    return {"asset_version": ASSET_VERSION}


templates = Jinja2Templates(directory=TEMPLATES_DIR, context_processors=[_asset_context])


class Redirect(Exception):
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
    raise Redirect("/setup" if auth.needs_setup() else "/login")


def _is_cross_site(request: Request) -> bool:
    """Whether browser request metadata says the submission came from another site.

    ``Sec-Fetch-Site`` is authoritative when the browser sends it; ``Origin`` is the
    fallback. Requests with neither header (curl, scripts, tests) are not blocked here —
    the token check below still applies to them.
    """
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None:
        return fetch_site not in {"same-origin", "none"}
    origin = request.headers.get("origin")
    if origin:
        return origin.rstrip("/") != str(request.base_url).rstrip("/")
    return False


async def verify_csrf(
    request: Request,
    session: Annotated[Session, Depends(require_session)],
) -> None:
    """Reject unsafe requests that do not carry the session's CSRF token.

    Two independent checks: the browser metadata rejected here, and the session's
    synchronizer token verified below. Registered as a dependency on every
    state-changing route, so a new route is protected by construction rather than by
    remembering.
    """
    if request.method not in _UNSAFE_METHODS:
        return
    if _is_cross_site(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cross-site request rejected")
    supplied = request.headers.get("X-CSRF-Token")
    if supplied is None and request.method == "POST":
        supplied = (await read_form(request)).get("csrf_token") or None
    auth: AuthService = request.app.state.auth
    if not auth.check_csrf(session, supplied):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")


def set_session_cookie(response: Response, sid: str, request: Request) -> None:
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


__all__ = [
    "ASSET_VERSION",
    "SESSION_COOKIE",
    "SESSION_COOKIE_MAX_AGE",
    "STATIC_DIR",
    "TEMPLATES_DIR",
    "Redirect",
    "asset_version",
    "current_session",
    "read_form",
    "require_session",
    "set_session_cookie",
    "templates",
    "verify_csrf",
]
