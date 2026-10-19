"""Entry point started by ``gilgamesh-web.service``.

This is infrastructure, not a user interface: the owner never runs it by hand
(constraint C2). A single Uvicorn worker is used deliberately — the dashboard's
server-sent-events bus lives in process memory, so a second worker would only
receive a share of the events.
"""

from __future__ import annotations

import uvicorn

from gilgamesh.config import Settings
from gilgamesh.util.logging import configure_logging
from gilgamesh.web.app import create_app

#: How long Uvicorn waits for in-flight requests before cancelling them. This exists
#: because of an ordering detail in Uvicorn: on SIGTERM it stops accepting connections,
#: then waits for the running request *tasks*, and only **afterwards** runs the
#: application's lifespan shutdown (``Server.shutdown`` in uvicorn/server.py). A dashboard
#: with an open server-sent-event stream is an in-flight request that never finishes by
#: itself, and the app's lifespan — where the bus closes its streams — is never reached.
#: Uvicorn's default is *no* timeout, so ``systemctl stop`` would hang until systemd's
#: ``TimeoutStopSec`` and then SIGKILL the process. With this bound the stream is
#: cancelled, the generator's ``finally`` drops the subscription, the lifespan runs, and
#: the service is down a few seconds after the signal (measured by the end-to-end test).
#:
#: Five seconds is far longer than any form post here needs. A cancelled SSE stream is
#: not an error for the browser: ``EventSource`` reconnects by itself.
GRACEFUL_SHUTDOWN_SECONDS = 5


def main() -> None:
    """Run the Gilgamesh web application.

    Logging goes to stderr, which systemd captures into the journal: the first-run
    setup token is delivered as a warning there, so ``journalctl -u gilgamesh-web`` is
    the first place an owner looks.
    """
    configure_logging()
    settings = Settings()
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS,
    )
