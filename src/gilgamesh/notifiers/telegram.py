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

from typing import TYPE_CHECKING, cast
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

if TYPE_CHECKING:
    import httpx

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

    body = _response_body(response)
    if response.is_success and body is not None and body.get("ok") is True:
        return DeliveryResult(ok=True, status_code=response.status_code)

    # Every failure shape, treated the same way: a non-2xx status, Telegram's own
    # documented error (HTTP 200 with "ok": false in the body — the body's Boolean
    # "ok" field is the verdict, so the status code alone can lie), or a body no
    # Telegram server could have written (an intermediary answered instead).
    description = body.get("description") if body is not None else None
    if isinstance(description, str) and description:
        error = description
    elif body is None and response.is_success:
        error = f"telegram returned {response.status_code} without a JSON body"
    else:
        error = f"telegram returned {response.status_code}"
    return DeliveryResult(
        ok=False,
        status_code=response.status_code,
        error=error,
        retry_after=_retry_after(response, body),
    )


def _response_body(response: httpx.Response) -> dict[str, object] | None:
    """Read the response body as a JSON object, tolerating anything else."""
    try:
        body: object = response.json()
    except (ValueError, TypeError):
        return None
    if not isinstance(body, dict):
        return None
    return cast("dict[str, object]", body)


def _retry_after(response: httpx.Response, body: dict[str, object] | None) -> float | None:
    """Seconds to wait: body ``parameters.retry_after`` first, then the header.

    The Bot API documents ``retry_after`` inside the optional ``ResponseParameters``
    object of a flood-control error; some intermediaries only bother with the header.
    """
    parameters = body.get("parameters") if body is not None else None
    if isinstance(parameters, dict):
        fields = cast("dict[str, object]", parameters)
        specified = fields.get("retry_after")
        if isinstance(specified, (int, float)):
            return max(0.0, float(specified))

    raw = response.headers.get("retry-after")
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
