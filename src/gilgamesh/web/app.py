"""FastAPI application factory and routes."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.sensors.fake import FakeDetector

TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=TEMPLATES_DIR)


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
        # The walking skeleton (milestone M1) proves the pipeline with the fake
        # detector; the real sensor process replaces this in milestone M8.
        for event in FakeDetector().events():
            database.insert_event(event)
        try:
            yield
        finally:
            database.close()

    app = FastAPI(title="Gilgamesh", lifespan=lifespan)

    @app.get("/api/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness probe. Unauthenticated on purpose: it reveals nothing."""
        return {"status": "ok"}

    @app.get("/api/events")
    async def list_events(request: Request) -> list[dict[str, Any]]:
        """Return the most recent events, newest first."""
        database: Database = request.app.state.db
        return [event.model_dump(mode="json") for event in database.list_events()]

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> Response:
        """Render the live dashboard."""
        database: Database = request.app.state.db
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={"events": database.list_events(), "settings": resolved},
        )

    return app
