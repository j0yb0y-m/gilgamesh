"""Logging configuration shared by every Gilgamesh process.

One place decides what a log line looks like, so the three units' output can be read
side by side in the journal. Both entry points send records to stderr, and systemd
captures stderr into the journal — the journal *is* the log file
(``journalctl -u gilgamesh-web``), with retention bounded by journald rather than by a
second, redundant log-rotation setup.

The first-run setup token is logged at WARNING by the web process, which is exactly why
this configuration must stay quiet by default and never log request bodies or secrets.
"""

from __future__ import annotations

import logging

#: Timestamp, level, logger name, message — the same shape for all three units.
FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_logging(level: int = logging.INFO) -> None:
    """Send Gilgamesh's own records to stderr at ``level``.

    ``basicConfig`` does nothing when handlers already exist, which is what makes this
    safe to call from a web process whose logging Uvicorn has already set up: Uvicorn
    configures only its own loggers, so the root logger is still ours to configure.
    """
    logging.basicConfig(level=level, format=FORMAT)


__all__ = ["FORMAT", "configure_logging"]
