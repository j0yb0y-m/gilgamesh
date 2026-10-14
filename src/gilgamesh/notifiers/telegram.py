"""Telegram bot notifications.

Verified against the official Bot API documentation (2026-10-14):
``https://core.telegram.org/bots/api``.

* Every request is served over HTTPS in the form
  ``https://api.telegram.org/bot<token>/METHOD_NAME``, and GET or POST are both allowed.
* Parameters may be passed as a query string, ``application/x-www-form-urlencoded``, or
  ``application/json``; this module uses JSON.
* ``sendMessage`` requires ``chat_id`` and ``text``.

The token is created with **@BotFather**, and the chat id is found with **@userinfobot**
(for a direct message) or from ``getUpdates`` (for a group). Both are entered by the owner
through the web UI and are never logged.

The token is percent-encoded into the URL path. Telegram tokens contain characters that
are legal in a URL path, but a mis-entered value containing ``/`` must not be able to
redirect the request somewhere else.
"""

from __future__ import annotations

from urllib.parse import quote

from gilgamesh.models import Event
from gilgamesh.notifiers.base import (
    TELEGRAM_MAX_MESSAGE_LENGTH,
    ChannelKind,
    DeliveryResult,
    HttpRequest,
    NotificationChannel,
    format_event_message,
)

TELEGRAM_API_BASE = "https://api.telegram.org"
DEFAULT_TIMEOUT_SECONDS = 10.0


def build_telegram_request(bot_token: str, chat_id: str, event: Event) -> HttpRequest:
    """Build the ``sendMessage`` request for ``event``."""
    # The colon is left literal to match Telegram's documented URL form; a stray "/"
    # in a mis-entered token is encoded so it cannot move the path segment.
    url = f"{TELEGRAM_API_BASE}/bot{quote(bot_token, safe=':')}/sendMessage"
    return HttpRequest(
        url=url,
        json={
            "chat_id": chat_id,
            "text": format_event_message(event, TELEGRAM_MAX_MESSAGE_LENGTH),
            "disable_web_page_preview": True,
        },
    )


async def http_transport(request: HttpRequest) -> DeliveryResult:
    """POST ``request`` with httpx and translate the response to a result."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS) as client:
            response = await client.post(request.url, json=request.json)
    except httpx.HTTPError as exc:
        return DeliveryResult(ok=False, error=str(exc))

    if response.is_success:
        return DeliveryResult(ok=True, status_code=response.status_code)

    # Telegram reports its own errors as HTTP 200 with "ok": false in the body, and
    # uses 429 for flood control, so both must be treated as failures.
    return DeliveryResult(
        ok=False,
        status_code=response.status_code,
        error=f"telegram returned {response.status_code}",
        retry_after=_retry_after(response),
    )


def _retry_after(response: object) -> float | None:
    """Read ``retry_after`` from a Telegram flood-control response."""
    headers = getattr(response, "headers", {})
    raw = headers.get("retry-after")
    if raw is None:
        return None
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return None


class TelegramChannel(NotificationChannel):
    """Sends alerts to a Telegram chat through a bot."""

    kind = ChannelKind.TELEGRAM

    async def _send(self, event: Event) -> DeliveryResult:
        token, chat_id = self._config.bot_token, self._config.chat_id
        if not token or not chat_id:
            return DeliveryResult(
                ok=False, error="Telegram bot token or chat id not configured", permanent=True
            )
        transport = self._transport if self._transport is not None else http_transport
        return await transport(build_telegram_request(token, chat_id, event))
