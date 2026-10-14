"""Notifier base: message formatting, retry with backoff, and a bounded send queue.

**The one rule that shapes this module: a notifier may never affect detection.**
Discord, Telegram, or an SMTP server being down, slow, or misconfigured must not add
latency to the sensor, fill memory, or raise into the pipeline. So:

* delivery happens on a background worker with a **bounded** queue — when the queue is
  full the *newest* alert is dropped and counted, because a stale alert is worth less
  than fresh ones;
* every failure is caught, retried with exponential backoff, and ultimately converted
  into a :class:`DeliveryResult` — nothing propagates;
* secrets are redacted out of error strings and logs before anything is recorded.

**Rate limits.** Discord signals throttling with HTTP 429 and ``Retry-After`` /
``X-RateLimit-*`` headers; Telegram limits bursts per chat. Rather than hard-coding a
per-provider quota, the transport reports ``retry_after`` when the server supplies it
and the worker otherwise backs off exponentially. *UNVERIFIED:* Discord's documented
per-webhook allowance (widely cited as 5 requests per 5 seconds) could not be read from
the JS-rendered docs page, so no constant is baked in — tracked in
``docs/research/09-open-questions.md``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from datetime import time as dt_time
from enum import StrEnum
from typing import Protocol

from gilgamesh.models import Event, EventType, Severity

logger = logging.getLogger(__name__)

#: Telegram rejects messages longer than this.
TELEGRAM_MAX_MESSAGE_LENGTH = 4096
#: Discord rejects messages longer than this.
DISCORD_MAX_MESSAGE_LENGTH = 2000

_EVENT_TYPE_LABELS: dict[EventType, str] = {
    EventType.ARP_SPOOF: "ARP spoofing",
    EventType.DNS_SPOOF: "DNS spoofing",
    EventType.DHCP_ROGUE: "Rogue DHCP",
    EventType.PORT_SCAN: "Port scan",
    EventType.SYN_FLOOD: "SYN flood",
    EventType.NEW_DEVICE: "New device",
    EventType.SURICATA_ALERT: "Suricata signature",
    EventType.TEST: "Test event",
}


class ChannelKind(StrEnum):
    """Supported alert channels."""

    DISCORD = "discord"
    TELEGRAM = "telegram"
    EMAIL = "email"


@dataclass(frozen=True, slots=True)
class ChannelConfig:
    """Everything the owner configures for one channel in the web UI.

    Secrets live here in memory and are never logged or echoed back to the UI. The
    channel *kind* is implied by the class that owns the config, not stored twice.
    """

    enabled: bool = True
    min_severity: Severity = Severity.MEDIUM
    #: Local time window during which nothing is sent, ``HH:MM`` inclusive.
    quiet_start: str | None = None
    quiet_end: str | None = None
    webhook_url: str | None = None
    bot_token: str | None = None
    chat_id: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    smtp_start_tls: bool = True
    sender: str | None = None
    recipients: tuple[str, ...] = ()

    @property
    def secrets(self) -> list[str]:
        """Values that must never appear in a log or an error message."""
        return [value for value in (self.webhook_url, self.bot_token, self.smtp_password) if value]


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """Outcome of one delivery attempt."""

    ok: bool
    status_code: int | None = None
    error: str | None = None
    retry_after: float | None = None
    #: True when retrying cannot help (misconfiguration, rejected webhook). Retrying a
    #: channel that has no URL configured just wastes the owner's time and ours.
    permanent: bool = False


@dataclass(frozen=True, slots=True)
class HttpRequest:
    """A transport-agnostic outbound request."""

    url: str
    json: dict[str, object] = field(default_factory=lambda: dict[str, object]())


class Transport(Protocol):
    """Sends a channel's payload and reports the outcome.

    Deliberately typed on ``object`` rather than one concrete request type: the HTTP
    channels post an :class:`HttpRequest`, email posts an ``EmailMessage``, and the
    retry/redaction logic in this module is identical for both.
    """

    async def __call__(self, request: object) -> DeliveryResult: ...


def format_event_message(event: Event, max_length: int = TELEGRAM_MAX_MESSAGE_LENGTH) -> str:
    """Render an event as the plain text sent to every channel."""
    label = _EVENT_TYPE_LABELS.get(event.type, event.type.value)
    lines = [
        f"[{event.severity.value.upper()}] {label}",
        event.summary,
    ]
    origin = " · ".join(part for part in (event.src_ip, event.src_mac, event.interface) if part)
    if origin:
        lines.append(f"From: {origin}")
    if event.dst_ip:
        lines.append(f"To: {event.dst_ip}")
    lines.append(f"Detector: {event.detector}")
    lines.append(f"Time: {event.ts.isoformat(timespec='seconds')}")

    message = "\n".join(lines)
    if len(message) > max_length:
        message = message[: max_length - 1] + "…"
    return message


def redact_secrets(text: str, secrets: Sequence[str]) -> str:
    """Replace every known secret in ``text`` with ``***``."""
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def _parse_hhmm(value: str) -> dt_time:
    hour, minute = (int(part) for part in value.split(":"))
    return dt_time(hour=hour, minute=minute)


class NotificationChannel:
    """Base class: severity/quiet-hour policy plus retrying delivery."""

    #: Which channel this is. Set by each subclass.
    kind: ChannelKind

    def __init__(
        self,
        config: ChannelConfig,
        *,
        transport: Transport | None = None,
        clock: Callable[[], datetime] | None = None,
        backoff_base: float = 0.5,
        max_attempts: int = 4,
    ) -> None:
        self._config = config
        self._transport: Transport | None = transport
        self._clock = clock if clock is not None else datetime.now
        self._backoff_base = backoff_base
        self._max_attempts = max_attempts
        self.deliver_count = 0

    @property
    def config(self) -> ChannelConfig:
        return self._config

    def wants(self, event: Event) -> bool:
        """Whether this channel should be told about ``event`` at all."""
        return self._config.enabled and event.severity.rank >= self._config.min_severity.rank

    def in_quiet_hours(self) -> bool:
        """Whether the current local time falls inside the configured quiet window."""
        start, end = self._config.quiet_start, self._config.quiet_end
        if not start or not end:
            return False
        now = self._clock().time()
        begins, finishes = _parse_hhmm(start), _parse_hhmm(end)
        if begins <= finishes:
            return begins <= now < finishes
        # Wraps midnight, e.g. 22:00 -> 07:00.
        return now >= begins or now < finishes

    async def deliver(self, event: Event) -> DeliveryResult:
        """Send ``event``, retrying transient failures with exponential backoff."""
        if self.in_quiet_hours():
            return DeliveryResult(ok=True, error="suppressed by quiet hours")

        self.deliver_count += 1
        for attempt in range(1, self._max_attempts + 1):
            try:
                result = await self._send(event)
            except Exception as exc:
                logger.warning("channel %s raised while sending: %s", self.kind, self._safe(exc))
                result = DeliveryResult(ok=False, error=self._safe(exc))

            # Redact unconditionally: httpx exception strings embed the request URL,
            # and for a Discord webhook that URL *is* the secret.
            result = DeliveryResult(
                ok=result.ok,
                status_code=result.status_code,
                error=self._safe_str(result.error),
                retry_after=result.retry_after,
                permanent=result.permanent,
            )
            if result.ok or result.permanent:
                return result
            if attempt == self._max_attempts:
                return result
            delay = (
                result.retry_after
                if result.retry_after is not None
                else (self._backoff_base * (2 ** (attempt - 1)))
            )
            await asyncio.sleep(delay)
        return DeliveryResult(ok=False, error="exhausted retries")

    async def _send(self, event: Event) -> DeliveryResult:
        """Perform one delivery attempt."""
        raise NotImplementedError

    def _safe(self, exc: BaseException) -> str:
        return redact_secrets(str(exc), self._config.secrets)

    def _safe_str(self, text: str | None) -> str | None:
        """Redact secrets out of a message that will be logged or returned."""
        if text is None:
            return None
        return redact_secrets(text, self._config.secrets)


class _Stop:
    """Sentinel telling the notifier worker to finish."""


_STOP = _Stop()


class Notifier:
    """Fans events out to channels on a bounded background queue."""

    def __init__(
        self,
        channels: Sequence[NotificationChannel],
        *,
        max_queue: int = 1000,
    ) -> None:
        self._channels = list(channels)
        self._queue: asyncio.Queue[Event | _Stop] = asyncio.Queue(maxsize=max_queue)
        self._max_queue = max_queue
        self._worker: asyncio.Task[None] | None = None
        self.dropped = 0

    async def start(self) -> None:
        """Start the background worker."""
        if self._worker is None:
            self._worker = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Stop the worker, finishing whatever is already queued."""
        if self._worker is None:
            return
        self._queue.put_nowait(_STOP)
        with contextlib.suppress(asyncio.CancelledError):
            await self._worker
        self._worker = None

    async def enqueue(self, event: Event) -> None:
        """Queue an event for delivery, waiting for room if the queue is not full."""
        await self._queue.put(event)

    def enqueue_nowait(self, event: Event) -> bool:
        """Queue an event without waiting; drop it if the queue is full."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1
            logger.warning("notifier queue full; dropped an alert")
            return False
        return True

    async def drain(self) -> None:
        """Wait until every queued event has been attempted."""
        await self._queue.join()

    async def _run(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                if isinstance(event, _Stop):
                    return
                await self._dispatch(event)
            finally:
                self._queue.task_done()

    async def _dispatch(self, event: Event) -> None:
        for channel in self._channels:
            if not channel.wants(event):
                continue
            result = await channel.deliver(event)
            if not result.ok:
                # Surfaced, never raised: a dead channel must not affect detection.
                logger.warning(
                    "channel %s could not deliver: %s",
                    channel.kind,
                    redact_secrets(result.error or "unknown", channel.config.secrets),
                )


__all__ = [
    "ChannelConfig",
    "ChannelKind",
    "DeliveryResult",
    "HttpRequest",
    "NotificationChannel",
    "Notifier",
    "Transport",
    "format_event_message",
    "redact_secrets",
]
