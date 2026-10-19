"""Periodic housekeeping: the retention the Settings page promises.

``retention_days`` was stored, rendered, and completely ignored — events, login
attempts and audit rows grew without bound, which on an appliance with an SD card is
exactly the failure the setting exists to prevent. This task is the one place that
deletes old rows, and it deliberately only deletes *delivered* events (``rowid`` at or
below the delivery cursor), so a slow delivery can never lose an alert that was
already detected.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime

from gilgamesh.db import Database
from gilgamesh.preferences import PreferencesStore

logger = logging.getLogger(__name__)

#: How often the sweep runs. Hourly is plenty for day-scale retention and keeps the
#: write amplification off the SD card.
SWEEP_SECONDS = 3600.0

# Login attempts are forensic breadcrumbs for lockout analysis; a week is enough.
LOGIN_ATTEMPT_RETENTION_SECONDS = 7 * 24 * 3600.0
# Audit entries answer "who changed what"; keep a year, they are tiny.
AUDIT_RETENTION_SECONDS = 365 * 24 * 3600.0
# A session idle for this long can only be an abandoned row (the auth timeouts are
# measured in hours), so sweeping it is pure cleanup.
STALE_SESSION_SECONDS = 30 * 24 * 3600.0


class MaintenanceTask:
    """Delete rows that have outlived their configured retention."""

    def __init__(
        self,
        database: Database,
        preferences: PreferencesStore,
        *,
        interval_seconds: float = SWEEP_SECONDS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._db = database
        self._preferences = preferences
        self._interval = interval_seconds
        self._clock = clock if clock is not None else time.time

    def run_once(self, delivered_rowid: int | None = None) -> dict[str, int]:
        """Prune every table and return the number of rows removed per table."""
        now = self._clock()
        retention_days = self._preferences.get().retention_days
        cutoff = datetime.fromtimestamp(now - retention_days * 86_400.0, UTC).isoformat()
        removed = {
            "events": self._db.prune_events(cutoff, delivered_rowid=delivered_rowid),
            "login_attempts": self._db.prune_login_attempts(now - LOGIN_ATTEMPT_RETENTION_SECONDS),
            "audit_log": self._db.prune_audit_log(now - AUDIT_RETENTION_SECONDS),
            "sessions": self._db.prune_expired_sessions(now - STALE_SESSION_SECONDS),
        }
        if any(removed.values()):
            logger.info("maintenance pruned %s", removed)
        return removed

    async def run(
        self,
        stop: asyncio.Event,
        delivered_rowid: Callable[[], int | None] | None = None,
    ) -> None:
        """Sweep until ``stop`` is set.

        ``delivered_rowid`` lets the caller pass the delivery cursor at prune time, so
        an event is never deleted before it has been delivered.
        """
        while not stop.is_set():
            try:
                self.run_once(delivered_rowid=delivered_rowid() if delivered_rowid else None)
            except Exception:
                logger.exception("maintenance sweep failed; will retry")
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._interval)
            except TimeoutError:
                continue


__all__ = [
    "AUDIT_RETENTION_SECONDS",
    "LOGIN_ATTEMPT_RETENTION_SECONDS",
    "STALE_SESSION_SECONDS",
    "SWEEP_SECONDS",
    "MaintenanceTask",
]
