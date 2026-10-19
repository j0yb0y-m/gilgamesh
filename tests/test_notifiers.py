"""M10 — notifier tests.

These tests never touch the network. Every channel is given an injected transport, so
what is verified here is Gilgamesh's behaviour — filtering, quiet hours, redaction,
retries, and bounded memory — not Discord's or Telegram's uptime.

The properties that matter most are negative: a broken channel must never slow down or
stop detection, and a secret must never appear in a log, an exception, or a message body.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, time
from pathlib import Path

import pytest

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.notifiers.base import (
    ChannelConfig,
    ChannelKind,
    DeliveryResult,
    Notifier,
    format_event_message,
    redact_secrets,
)
from gilgamesh.notifiers.discord import DiscordChannel, build_discord_request
from gilgamesh.notifiers.email import EmailChannel, build_email_message
from gilgamesh.notifiers.telegram import (
    TelegramChannel,
    build_telegram_request,
    http_transport,
)

SECRET = "https://discord.com/api/webhooks/123/tok-SUPERSECRET"
BOT_TOKEN = "123456:ABC-DEF-supersecret"


def make_event(severity: Severity = Severity.HIGH) -> Event:
    return Event(
        type=EventType.ARP_SPOOF,
        severity=severity,
        detector="arp",
        summary="Gateway 10.0.0.1 is being advertised as de:ad:be:ef",
        src_mac="de:ad:be:ef:00:01",
        src_ip="10.0.0.2",
        details={"reason": "gateway_mac_changed", "previous_mac": "aa:bb:cc:00:00:01"},
    )


class FakeTransport:
    """Records requests and replays a scripted sequence of outcomes.

    Once the script runs out the last outcome repeats, which models a channel that is
    permanently down rather than recovering on its own.
    """

    def __init__(self, outcomes: list[DeliveryResult] | None = None) -> None:
        self.requests: list[object] = []
        self._outcomes = list(outcomes or [])

    async def __call__(self, request: object) -> DeliveryResult:
        self.requests.append(request)
        if self._outcomes:
            return self._outcomes.pop(0) if len(self._outcomes) > 1 else self._outcomes[0]
        return DeliveryResult(ok=True, status_code=204)


# --- message formatting -------------------------------------------------------


def test_message_contains_severity_type_and_summary() -> None:
    message = format_event_message(make_event())

    assert "HIGH" in message
    assert "ARP spoofing" in message
    assert "Gateway 10.0.0.1 is being advertised" in message
    assert "de:ad:be:ef:00:01" in message


def test_message_stays_within_telegram_limits() -> None:
    """Telegram rejects messages over 4096 characters."""
    event = make_event().model_copy(update={"summary": "x" * 5000})

    assert len(format_event_message(event)) <= 4096


def test_redaction_masks_secrets() -> None:
    text = f"failed to post to {SECRET} using {BOT_TOKEN}"

    redacted = redact_secrets(text, secrets=[SECRET, BOT_TOKEN])

    assert SECRET not in redacted
    assert BOT_TOKEN not in redacted
    assert "***" in redacted


# --- request shapes -----------------------------------------------------------


def test_discord_request_shape() -> None:
    request = build_discord_request(SECRET, make_event())

    assert str(request.url) == f"{SECRET}?wait=true"
    assert request.json["content"]


def test_telegram_request_shape() -> None:
    request = build_telegram_request(BOT_TOKEN, "-1001234567890", make_event())

    assert str(request.url) == f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    assert request.json["chat_id"] == "-1001234567890"
    assert "content" not in request.json
    assert request.json["text"]


def test_telegram_url_encodes_the_token() -> None:
    """A token with path separators must not escape its position in the URL."""
    request = build_telegram_request("bad/token", "1", make_event())

    assert str(request.url) == "https://api.telegram.org/botbad%2Ftoken/sendMessage"


# --- the real HTTP transport (Telegram response-body semantics) ----------------


class _StubTelegramResponse:
    """A minimal ``httpx.Response`` lookalike driven by a canned body.

    ``json()`` raises exactly like httpx when the body is not JSON, which models an
    intermediary (proxy, captive portal) answering 200 with its own page.
    """

    def __init__(
        self,
        status_code: int,
        body: object,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> object:
        if isinstance(self._body, str):
            raise json.JSONDecodeError("not JSON", self._body, 0)
        return self._body


def _stub_httpx(monkeypatch: pytest.MonkeyPatch, response: _StubTelegramResponse) -> None:
    """Point ``httpx.AsyncClient`` at one canned response; no network in tests."""
    import httpx

    class _StubAsyncClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        async def __aenter__(self) -> _StubAsyncClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def post(self, url: object, **kwargs: object) -> _StubTelegramResponse:
            self.last = (url, kwargs.get("json"))
            return response

    monkeypatch.setattr(httpx, "AsyncClient", _StubAsyncClient)


async def test_telegram_200_with_ok_false_is_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Bot API reports its own errors as HTTP 200 with ``ok: false`` in the body."""
    _stub_httpx(
        monkeypatch,
        _StubTelegramResponse(
            200,
            {"ok": False, "error_code": 400, "description": "Bad Request: chat not found"},
        ),
    )

    result = await http_transport(build_telegram_request(BOT_TOKEN, "12", make_event()))

    assert result.ok is False
    assert "chat not found" in (result.error or "")
    assert result.status_code == 200


async def test_telegram_200_with_ok_true_is_a_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_httpx(monkeypatch, _StubTelegramResponse(200, {"ok": True, "result": {"message_id": 7}}))

    result = await http_transport(build_telegram_request(BOT_TOKEN, "12", make_event()))

    assert result.ok is True
    assert result.status_code == 200


async def test_telegram_200_with_an_unreadable_body_is_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 200 whose body no Telegram client can parse is not a delivered alert."""
    _stub_httpx(monkeypatch, _StubTelegramResponse(200, "<html>not ours</html>"))

    result = await http_transport(build_telegram_request(BOT_TOKEN, "12", make_event()))

    assert result.ok is False
    assert result.status_code == 200


def test_telegram_retry_after_prefers_the_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flood-control seconds arrive as ``parameters.retry_after`` (ResponseParameters)."""
    _stub_httpx(
        monkeypatch,
        _StubTelegramResponse(
            429,
            {"ok": False, "parameters": {"retry_after": 7}},
            headers={"retry-after": "3"},
        ),
    )

    result = asyncio.run(http_transport(build_telegram_request(BOT_TOKEN, "12", make_event())))

    assert result.retry_after == 7.0


def test_telegram_retry_after_falls_back_to_the_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_httpx(
        monkeypatch,
        _StubTelegramResponse(429, None, headers={"retry-after": "3"}),
    )

    result = asyncio.run(http_transport(build_telegram_request(BOT_TOKEN, "12", make_event())))

    assert result.retry_after == 3.0
    assert result.ok is False


def test_email_message_has_subject_and_body() -> None:
    message = build_email_message(
        sender="gilgamesh@example.invalid",
        recipients=["owner@example.invalid"],
        event=make_event(),
    )

    assert "[Gilgamesh]" in message.subject
    assert "HIGH" in message.subject
    assert "Gateway 10.0.0.1" in message.body


# --- severity filtering -------------------------------------------------------


@pytest.mark.parametrize(
    ("min_severity", "event_severity", "expected"),
    [
        (Severity.MEDIUM, Severity.HIGH, True),
        (Severity.HIGH, Severity.LOW, False),
        (Severity.CRITICAL, Severity.HIGH, False),
        (Severity.INFO, Severity.CRITICAL, True),
    ],
)
def test_minimum_severity_filter(
    min_severity: Severity, event_severity: Severity, expected: bool
) -> None:
    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET, min_severity=min_severity),
        transport=FakeTransport(),
    )

    assert channel.wants(make_event(event_severity)) is expected


def test_disabled_channel_wants_nothing() -> None:
    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET, enabled=False), transport=FakeTransport()
    )

    assert channel.wants(make_event()) is False


# --- quiet hours --------------------------------------------------------------


def test_quiet_hours_suppress_delivery() -> None:
    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET, quiet_start="22:00", quiet_end="07:00"),
        transport=FakeTransport(),
        clock=lambda: _at("23:30"),
    )

    assert channel.in_quiet_hours() is True


def test_outside_quiet_hours_delivers() -> None:
    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET, quiet_start="22:00", quiet_end="07:00"),
        transport=FakeTransport(),
        clock=lambda: _at("12:00"),
    )

    assert channel.in_quiet_hours() is False


def test_quiet_hours_wrapping_midnight() -> None:
    """22:00 -> 07:00 must cover 00:30, which a naive comparison gets wrong."""
    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET, quiet_start="22:00", quiet_end="07:00"),
        transport=FakeTransport(),
        clock=lambda: _at("00:30"),
    )

    assert channel.in_quiet_hours() is True


def _at(hhmm: str) -> datetime:
    hour, minute = (int(part) for part in hhmm.split(":"))
    return datetime.combine(datetime.now().date(), time(hour, minute))


# --- retries and resilience ---------------------------------------------------


async def test_transient_failure_is_retried() -> None:
    transport = FakeTransport(
        [
            DeliveryResult(ok=False, status_code=500, error="server error"),
            DeliveryResult(ok=True, status_code=204),
        ]
    )
    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET), transport=transport, backoff_base=0.0
    )

    result = await channel.deliver(make_event())

    assert result.ok is True
    assert len(transport.requests) == 2


async def test_permanent_failure_gives_up_after_max_attempts() -> None:
    transport = FakeTransport([DeliveryResult(ok=False, status_code=400, error="bad webhook")])
    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET),
        transport=transport,
        backoff_base=0.0,
        max_attempts=3,
    )

    result = await channel.deliver(make_event())

    assert result.ok is False
    assert len(transport.requests) == 3


async def test_retry_after_header_is_respected() -> None:
    transport = FakeTransport(
        [
            DeliveryResult(ok=False, status_code=429, error="slow down", retry_after=0.01),
            DeliveryResult(ok=True, status_code=204),
        ]
    )
    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET), transport=transport, backoff_base=0.0
    )

    result = await channel.deliver(make_event())

    assert result.ok is True
    assert len(transport.requests) == 2


async def test_delivery_never_raises_into_the_pipeline() -> None:
    async def exploding(request: object) -> DeliveryResult:
        msg = "transport exploded"
        raise RuntimeError(msg)

    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET), transport=exploding, backoff_base=0.0, max_attempts=1
    )

    result = await channel.deliver(make_event())

    assert result.ok is False
    assert "transport exploded" in (result.error or "")


async def test_errors_are_redacted() -> None:
    async def leaky(request: object) -> DeliveryResult:
        return DeliveryResult(ok=False, status_code=500, error=f"post to {SECRET} failed")

    channel = DiscordChannel(
        ChannelConfig(webhook_url=SECRET), transport=leaky, backoff_base=0.0, max_attempts=1
    )

    result = await channel.deliver(make_event())

    assert SECRET not in (result.error or "")


# --- the notifier queue -------------------------------------------------------


async def test_notifier_delivers_queued_events() -> None:
    transport = FakeTransport()
    channel = DiscordChannel(ChannelConfig(webhook_url=SECRET), transport=transport)
    notifier = Notifier([channel])

    await notifier.start()
    await notifier.enqueue(make_event())
    await notifier.drain()

    assert len(transport.requests) == 1
    await notifier.stop()


async def test_notifier_drops_when_the_queue_is_full() -> None:
    """Bounded memory: a slow channel must not grow the queue without limit."""

    class SlowTransport:
        def __init__(self) -> None:
            self.count = 0

        async def __call__(self, request: object) -> DeliveryResult:
            self.count += 1
            await asyncio.sleep(0)
            return DeliveryResult(ok=True, status_code=204)

    channel = DiscordChannel(ChannelConfig(webhook_url=SECRET), transport=SlowTransport())
    notifier = Notifier([channel], max_queue=2)

    await notifier.start()
    for _ in range(10):
        notifier.enqueue_nowait(make_event())
    await notifier.drain()
    await notifier.stop()

    assert channel.deliver_count <= 2


async def test_notifier_survives_a_failing_channel() -> None:
    failing = DiscordChannel(
        ChannelConfig(webhook_url=SECRET),
        transport=FakeTransport([DeliveryResult(ok=False, status_code=500, error="down")]),
        backoff_base=0.0,
        max_attempts=1,
    )
    working = DiscordChannel(
        ChannelConfig(webhook_url="https://example.invalid/hook"), transport=FakeTransport()
    )
    notifier = Notifier([failing, working])

    await notifier.start()
    await notifier.enqueue(make_event())
    await notifier.drain()

    assert working.deliver_count == 1
    await notifier.stop()


async def test_telegram_and_email_channels_are_constructible() -> None:
    """Every channel reports its kind and honours the same policy base class."""
    telegram = TelegramChannel(ChannelConfig(bot_token=BOT_TOKEN, chat_id="1"))
    email = EmailChannel(
        ChannelConfig(
            smtp_host="smtp.example.invalid",
            sender="gilgamesh@example.invalid",
            recipients=("owner@example.invalid",),
        )
    )

    assert telegram.kind is ChannelKind.TELEGRAM
    assert email.kind is ChannelKind.EMAIL
    assert telegram.wants(make_event()) is True
    assert email.wants(make_event()) is True


async def test_email_channel_delivers_through_injected_transport() -> None:
    sent: list[object] = []

    async def transport(request: object) -> DeliveryResult:
        sent.append(request)
        return DeliveryResult(ok=True, status_code=250)

    channel = EmailChannel(
        ChannelConfig(
            smtp_host="smtp.example.invalid",
            sender="gilgamesh@example.invalid",
            recipients=("owner@example.invalid",),
        ),
        transport=transport,
    )

    result = await channel.deliver(make_event())

    assert result.ok is True
    assert len(sent) == 1


async def test_misconfiguration_is_not_retried() -> None:
    """A channel with no URL cannot succeed; retrying only wastes the backoff budget."""
    transport = FakeTransport()
    channel = DiscordChannel(
        ChannelConfig(), transport=transport, backoff_base=60.0, max_attempts=4
    )

    result = await channel.deliver(make_event())

    assert result.ok is False
    assert result.permanent is True
    assert transport.requests == []


async def test_email_without_configuration_fails_cleanly() -> None:
    channel = EmailChannel(ChannelConfig())

    result = await channel.deliver(make_event())

    assert result.ok is False
    assert "not configured" in (result.error or "")


def test_notifier_never_logs_secrets(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    channel = DiscordChannel(ChannelConfig(webhook_url=SECRET), transport=FakeTransport())
    notifier = Notifier([channel])

    with caplog.at_level(logging.DEBUG):
        notifier.enqueue_nowait(make_event())

    assert SECRET not in caplog.text
