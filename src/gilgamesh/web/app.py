"""FastAPI application factory: lifespan, middleware, and router wiring.

Route handlers live in :mod:`gilgamesh.web.routes` (one module per page area) and the
shared dependencies they use live in :mod:`gilgamesh.web.deps`. This module only builds
the app: it owns the resources that must outlive a request (database, auth, rules,
event bus, and the device/channel stores), installs the security-header middleware, and
mounts the vendored static assets.

Wiring lives here rather than in each router so there is exactly one place that decides
which routers exist and in what order they are included.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from gilgamesh.channels import ChannelStore
from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.rules import RuleConfigService, default_catalogue
from gilgamesh.rules_update import RulesUpdateResult, refresh_rules
from gilgamesh.sensors.fake import FakeDetector
from gilgamesh.web.auth import create_auth_service
from gilgamesh.web.deps import STATIC_DIR, Redirect
from gilgamesh.web.routes import (
    alerts,
    auth,
    dashboard,
    devices,
    health,
    notifications,
    rules,
)
from gilgamesh.web.routes import (
    settings as settings_routes,
)
from gilgamesh.web.sse import EventBus

#: Type of the callable the Health page invokes to update rules. Injectable through
#: ``app.state.rules_update`` so tests never shell out to ``suricata-update``.
RulesUpdater = Callable[[], RulesUpdateResult]


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
        app.state.devices = DeviceStore(database)
        app.state.channels = ChannelStore(database)
        app.state.bus = EventBus()
        # Transport overrides for the notification channels, keyed by ChannelKind. Empty
        # in production (each channel builds its own HTTP transport); tests inject fakes.
        app.state.channel_transports = {}
        # The walking skeleton (milestone M1) proves the pipeline with the fake
        # detector; the real sensor process replaces this in milestone M8.
        for event in FakeDetector().events():
            database.insert_event(event)

        def update_rules() -> RulesUpdateResult:
            return refresh_rules(settings=resolved, rules=app.state.rules)

        app.state.rules_update = update_rules
        try:
            yield
        finally:
            await app.state.bus.unsubscribe_all()
            database.close()

    app = FastAPI(title="Gilgamesh", lifespan=lifespan)
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: object) -> Response:
        """Attach the security headers every response must carry.

        The CSP omits ``unsafe-eval``, which is why Alpine's **CSP** build is vendored:
        the default build cannot run without it.
        """
        response = await call_next(request)  # type: ignore[operator, no-any-return]
        h = response.headers  # type: ignore[no-any-return]
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        return response  # type: ignore[no-any-return]

    @app.exception_handler(Redirect)
    async def _redirect_handler(request: Request, exc: Redirect) -> Response:
        return RedirectResponse(exc.location, status_code=status.HTTP_303_SEE_OTHER)

    for page_router in (
        auth.router,
        dashboard.router,
        alerts.router,
        rules.router,
        devices.router,
        notifications.router,
        health.router,
        settings_routes.router,
    ):
        app.include_router(page_router)

    return app


__all__ = ["create_app"]
