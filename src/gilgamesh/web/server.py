"""Entry point started by ``gilgamesh-web.service``.

This is infrastructure, not a user interface: the owner never runs it by hand
(constraint C2). A single Uvicorn worker is used deliberately — the dashboard's
server-sent-events bus lives in process memory, so a second worker would only
receive a share of the events.
"""

from __future__ import annotations

import uvicorn

from gilgamesh.config import Settings
from gilgamesh.web.app import create_app


def main() -> None:
    """Run the Gilgamesh web application."""
    settings = Settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
