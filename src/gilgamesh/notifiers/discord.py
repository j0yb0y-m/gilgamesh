"""Discord webhook notifications.

Verified against the Discord developer documentation (2026-10-14):
``https://discord.com/developers/docs/resources/webhook``. Webhooks post JSON with a
``content`` field and need no bot user or authentication. Appending ``wait=true`` makes
Discord return the created message, so a non-2xx response is a real delivery failure and
can be retried honestly — without it, Discord answers ``204`` even when the message was
rate-limited away.

**UNVERIFIED:** the documented per-webhook allowance (widely cited as 5 requests per
5 seconds) could not be read from the JS-rendered documentation page, so no constant is
baked in here. Throttling is handled generically: HTTP 429 plus the ``Retry-After`` /
``X-RateLimit-*`` headers, falling back to exponential backoff. See
``docs/research/09-open-questions.md``.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from gilgamesh.models import Event
from gilgamesh.notifiers.base import (
    DISCORD_MAX_MESSAGE_LENGTH,
    ChannelKind,
    DeliveryResult,
    HttpRequest,
    NotificationChannel,
    format_event_message,
)

DEFAULT_TIMEOUT_SECONDS = 10.0


def build_discord_request(webhook_url: str, event: Event) -> HttpRequest:
    """Build the request that posts ``event`` to a Discord webhook."""
    parts = urlsplit(webhook_url)
    query = "&".join(filter(None, (parts.query, "wait=true")))
    url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
    return HttpRequest(
        url=url,
        json={
            "content": format_event_message(event, DISCORD_MAX_MESSAGE_LENGTH),
            # Never let a mention ping a human for a scan on their own LAN.
            "allowed_mentions": {"parse": []},
        },
    )


async def http_transport(request: HttpRequest) -> DeliveryResult:
    """POST ``request`` with httpx and translate the response to a result."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS) as client:
            response = await client.post(request.url, json=request.json, follow_redirects=False)
    except httpx.HTTPError as exc:
        return DeliveryResult(ok=False, error=str(exc))

    if response.is_success:
        return DeliveryResult(ok=True, status_code=response.status_code)

    retry_after = _retry_after(response)
    return DeliveryResult(
        ok=False,
        status_code=response.status_code,
        error=f"discord returned {response.status_code}",
        retry_after=retry_after,
    )


def _retry_after(response: object) -> float | None:
    """Read the server-supplied retry delay, in seconds."""
    headers = getattr(response, "headers", {})
    for name in ("retry-after", "x-ratelimit-reset-after"):
        raw = headers.get(name)
        if raw is None:
            continue
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            continue
    return None


class DiscordChannel(NotificationChannel):
    """Posts alerts to a Discord channel through an incoming webhook."""

    kind = ChannelKind.DISCORD

    async def _send(self, event: Event) -> DeliveryResult:
        webhook_url = self._config.webhook_url
        if not webhook_url:
            return DeliveryResult(
                ok=False, error="no Discord webhook URL configured", permanent=True
            )
        transport = self._transport if self._transport is not None else http_transport
        return await transport(build_discord_request(webhook_url, event))
