"""Drain newly stored events into the live feed and the notification channels.

The sensor process writes every surviving event into SQLite and knows nothing about
the web tier; the web process never sees the sensor's memory. Nothing used to bridge
the two, so the dashboard's "live" feed never received a frame and Discord/Telegram/
email were only ever exercised by the *Send test* button. This task is that bridge:
it polls the ``events`` table for rows it has not processed yet, publishes each one on
the in-process :class:`EventBus` (server-sent events for every open browser tab), and
hands it to the :class:`Notifier` fan-out.

**The delivery position is durable.** The last delivered ``rowid`` is written to
``app_settings``, so an event that arrives while the web process is restarting is
delivered once the process is back, instead of being silently skipped. Delivery is
therefore *at least once*: a crash between "published" and "cursor persisted" can
repeat one batch, which is the safe direction for an alerting system.

**Why polling.** The two processes share a file and nothing else; SQLite has no
cross-process notification channel. A two-second poll of an indexed ``rowid`` range
costs a few microseconds and keeps the design honest — no hidden broker, no daemon.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping

from gilgamesh.channels import ChannelRecord, ChannelStore
from gilgamesh.db import Database
from gilgamesh.models import Event
from gilgamesh.notifiers.base import ChannelKind, Notifier, Transport

logger = logging.getLogger(__name__)

#: ``app_settings`` key holding the last delivered event rowid.
CURSOR_KEY = "delivery_cursor"

#: One poll moves at most this many rows, so an alert flood cannot monopolise the task.
BATCH_SIZE = 200

#: How long between polls. The sensor's own alert pipeline already bounds the rate, so
#: a faster poll would only spend Pi cycles.
POLL_SECONDS = 2.0


class DeliveryService:
    """Poll for new events; publish them and notify every willing channel."""

    def __init__(
        self,
        database: Database,
        channels: ChannelStore,
        publish: Callable[[Event], Awaitable[None]],
        *,
        transports: Mapping[ChannelKind, Transport] | None = None,
        poll_seconds: float = POLL_SECONDS,
    ) -> None:
        self._db = database
        self._channels = channels
        self._publish = publish
        self._transports = dict(transports or {})
        self._poll_seconds = poll_seconds
        self._cursor = self._load_cursor()
        self._snapshot: list[ChannelRecord] = []
        self._notifier: Notifier | None = None

    @property
    def cursor(self) -> int:
        """The rowid after which the next poll starts."""
        return self._cursor

    @property
    def notifier(self) -> Notifier | None:
        """The running fan-out, or ``None`` while no channel is enabled."""
        return self._notifier

    def _load_cursor(self) -> int:
        stored = self._db.get_setting(CURSOR_KEY)
        if stored is None:
            # First run against this database: start from "now" so a fresh install does
            # not replay rows that predate delivery wiring. Once written, the cursor
            # survives restarts and later downtime is covered.
            cursor = self._db.max_event_rowid()
            self._db.set_setting(CURSOR_KEY, str(cursor))
            return cursor
        try:
            return int(stored)
        except ValueError:
            return self._db.max_event_rowid()

    async def _sync_notifier(self) -> None:
        """Rebuild the fan-out whenever the owner changes the channel configuration."""
        records = [record for record in self._channels.list() if record.enabled]
        if records == self._snapshot:
            return
        await self._retire_notifier()
        self._snapshot = records
        if not records:
            return
        channels = [
            self._channels.build_channel(record, transport=self._transports.get(record.kind))
            for record in records
        ]
        notifier = Notifier(channels)
        await notifier.start()
        self._notifier = notifier

    async def _retire_notifier(self) -> None:
        if self._notifier is not None:
            await self._notifier.stop()
            self._notifier = None

    async def poll_once(self) -> int:
        """Process every pending event; returns how many were handled."""
        await self._sync_notifier()
        processed = 0
        while True:
            rows = self._db.events_after_rowid(self._cursor, BATCH_SIZE)
            if not rows:
                return processed
            for rowid, event in rows:
                await self._publish(event)
                if self._notifier is not None:
                    self._notifier.enqueue_nowait(event)
                self._cursor = rowid
                processed += 1
            self._db.set_setting(CURSOR_KEY, str(self._cursor))

    async def run(self, stop: asyncio.Event) -> None:
        """Poll until ``stop`` is set."""
        while not stop.is_set():
            try:
                await self.poll_once()
            except Exception:
                # A storage hiccup must not kill the loop; the next poll retries.
                logger.exception("delivery poll failed; will retry")
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._poll_seconds)
            except TimeoutError:
                continue

    async def stop(self) -> None:
        """Stop the fan-out worker, letting whatever is queued finish."""
        await self._retire_notifier()


__all__ = ["BATCH_SIZE", "CURSOR_KEY", "POLL_SECONDS", "DeliveryService"]
