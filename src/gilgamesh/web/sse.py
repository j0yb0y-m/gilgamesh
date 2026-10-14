"""Server-sent events: the live alert feed.

**Why SSE and not WebSockets.** The dashboard only needs the server to *push* alerts; it
never needs the browser to push anything back. SSE is plain HTTP over one long-lived
response, so it survives proxies, needs no extra library, and reconnects by itself.

**Why a single worker.** The bus lives in this process's memory. Uvicorn is therefore run
with **one worker** — with two, a connected client would only see the events published by
the worker that happens to serve it. That is an operational constraint on
``gilgamesh-web.service``, not something to discover in production.

Events are published by :meth:`EventBus.publish` and drained by each connected client, so
one slow browser cannot hold up another.

**Wire format.** ``EventSourceResponse`` takes a stream of **bytes**, not model objects;
frames are built with FastAPI's own ``format_sse_event``, so the encoding is the
framework's and not a hand-rolled string.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from fastapi.sse import format_sse_event

logger = logging.getLogger(__name__)

#: How often a comment is sent to keep intermediaries from closing an idle connection.
KEEPALIVE_SECONDS = 25.0
_EVENT_NAME = "alert"


@dataclass(slots=True, eq=False)
class Subscription:
    """One connected client.

    ``eq=False`` keeps the default identity-based ``__hash__``: subscriptions are tracked
    in a set, and two clients with identical empty queues are still two clients.
    """

    queue: asyncio.Queue[bytes | None] = field(default_factory=lambda: asyncio.Queue(maxsize=100))

    def close(self) -> None:
        """Wake the subscriber, even if its queue is full.

        The sentinel must actually arrive: a subscriber that has stopped draining (a
        stalled browser tab) fills its bounded queue, so ``put_nowait(None)`` alone would
        raise ``QueueFull`` and the stream would never end. Discarding the undelivered
        frames is correct here — the process is going away.
        """
        while True:
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self.queue.put_nowait(None)


def encode_payload(event: object) -> str:
    """Serialise an event to the JSON string carried in the ``data:`` field."""
    if isinstance(event, str):
        return event
    dump: Any = getattr(event, "model_dump_json", None)
    if callable(dump):
        return str(dump())
    return json.dumps(event, default=str)


class EventBus:
    """Fan-out of events to every connected dashboard."""

    def __init__(self) -> None:
        self._subscriptions: set[Subscription] = set()
        self._lock = asyncio.Lock()

    @property
    def subscriber_count(self) -> int:
        """How many dashboards are currently listening."""
        return len(self._subscriptions)

    async def publish(self, event: object) -> None:
        """Send an event to every subscriber, dropping it for any that cannot keep up.

        A subscriber whose queue is full is skipped rather than allowed to block the
        publisher: a stalled browser tab must never slow down detection.
        """
        frame = format_sse_event(data_str=encode_payload(event), event=_EVENT_NAME)
        async with self._lock:
            targets = list(self._subscriptions)
        for subscription in targets:
            try:
                subscription.queue.put_nowait(frame)
            except asyncio.QueueFull:
                logger.warning("dropping an event for a slow SSE subscriber")

    async def subscribe(self) -> AsyncIterator[bytes]:
        """Yield wire-format frames for one client until it disconnects."""
        subscription = Subscription()
        async with self._lock:
            self._subscriptions.add(subscription)
        try:
            while True:
                try:
                    frame = await asyncio.wait_for(
                        subscription.queue.get(), timeout=KEEPALIVE_SECONDS
                    )
                except TimeoutError:
                    # A comment keeps proxies from reaping an idle connection without
                    # being delivered to the browser as a message.
                    yield format_sse_event(comment="ping")
                    continue
                if frame is None:
                    return
                yield frame
        finally:
            async with self._lock:
                self._subscriptions.discard(subscription)

    async def unsubscribe_all(self) -> None:
        """Close every stream; used when the application shuts down."""
        async with self._lock:
            targets = list(self._subscriptions)
            self._subscriptions.clear()
        for subscription in targets:
            subscription.close()
