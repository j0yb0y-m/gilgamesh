"""FastAPI application factory: lifespan, middleware, and router wiring.

Route handlers live in :mod:`gilgamesh.web.routes` (one module per page area) and the
shared dependencies they use live in :mod:`gilgamesh.web.deps`. This module only builds
the app: it owns the resources that must outlive a request (database, auth, rules,
event bus, device/channel stores, and the background delivery loop), installs the
security middleware, and mounts the vendored static assets.

Wiring lives here rather than in each router so there is exactly one place that decides
which routers exist and in what order they are included.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from gilgamesh.channels import ChannelStore
from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.notifiers.base import ChannelKind, Transport
from gilgamesh.preferences import PreferencesStore
from gilgamesh.rules import RuleConfigService, default_catalogue
from gilgamesh.rules_update import RulesUpdateResult, refresh_rules
from gilgamesh.web.auth import create_auth_service
from gilgamesh.web.delivery import DeliveryService
from gilgamesh.web.deps import STATIC_DIR, Redirect
from gilgamesh.web.maintenance import MaintenanceTask
from gilgamesh.web.middleware import (
    BodySizeLimitMiddleware,
    RequestTooLarge,
    SecurityHeadersMiddleware,
)
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

logger = logging.getLogger(__name__)

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
        auth = create_auth_service(database)
        app.state.auth = auth
        app.state.rules = RuleConfigService(database, default_catalogue())
        app.state.devices = DeviceStore(database)
        app.state.channels = ChannelStore(database)
        app.state.preferences = PreferencesStore(database)
        app.state.bus = EventBus()
        # Transport overrides for the notification channels, keyed by ChannelKind. Empty
        # in production (each channel builds its own HTTP transport); tests inject fakes.
        channel_transports: dict[ChannelKind, Transport] = {}
        app.state.channel_transports = channel_transports

        setup_token = auth.ensure_setup_token()
        if setup_token is not None:
            logger.warning(
                "first-run setup is open: enter setup token %r in the wizard "
                "(journalctl -u gilgamesh-web | grep setup)",
                setup_token,
            )

        # The two background loops that make storage visible to the outside world:
        # one delivers new events (live feed + notifiers), one enforces retention.
        delivery = DeliveryService(
            database,
            app.state.channels,
            app.state.bus.publish,
            transports=channel_transports,
        )
        maintenance = MaintenanceTask(database, app.state.preferences)
        app.state.delivery = delivery
        stop = asyncio.Event()
        tasks = [
            asyncio.create_task(delivery.run(stop), name="gilgamesh-delivery"),
            asyncio.create_task(
                maintenance.run(stop, delivered_rowid=lambda: delivery.cursor),
                name="gilgamesh-maintenance",
            ),
        ]

        def update_rules() -> RulesUpdateResult:
            return refresh_rules(settings=resolved)

        app.state.rules_update = update_rules
        try:
            yield
        finally:
            stop.set()
            try:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)
            except TimeoutError:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            await delivery.stop()
            await app.state.bus.unsubscribe_all()
            database.close()

    api_docs = resolved.enable_api_docs
    app = FastAPI(
        title="Gilgamesh",
        lifespan=lifespan,
        docs_url="/docs" if api_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if api_docs else None,
    )
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    if resolved.host_allowlist != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=resolved.host_allowlist)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=resolved.max_request_body_bytes)

    @app.exception_handler(Redirect)
    async def _redirect_handler(request: Request, exc: Redirect) -> Response:
        return RedirectResponse(exc.location, status_code=status.HTTP_303_SEE_OTHER)

    @app.exception_handler(RequestTooLarge)
    async def _too_large_handler(request: Request, exc: RequestTooLarge) -> Response:
        return PlainTextResponse("Request body too large", status_code=413)

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

    # Wrap the fully built middleware stack in the header middleware. Assigning the
    # stack directly (rather than using ``@app.middleware("http")``) puts the headers
    # *outside* ``ServerErrorMiddleware``, so even the framework's synthesized 500 page
    # carries them. The app object stays a FastAPI instance, so ``app.state`` and the
    # tests that use it are unaffected.
    app.middleware_stack = SecurityHeadersMiddleware(app.build_middleware_stack())
    return app


__all__ = ["RulesUpdater", "create_app"]
