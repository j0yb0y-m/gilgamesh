"""The bridge between the sensor's database writes and the owner's eyes.

The sensor process stores events; the web process is the only one that can show or send
them, and the two share nothing but SQLite. These tests pin down that bridge: an event
stored after start-up reaches the live feed and the channels, an event stored while the
web process was down is delivered when it returns, and retention never deletes something
delivery has not seen yet.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gilgamesh.channels import ChannelStore
from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.notifiers.base import ChannelKind, DeliveryResult, HttpRequest
from gilgamesh.preferences import PreferencesStore
from gilgamesh.web.delivery import CURSOR_KEY, DeliveryService
from gilgamesh.web.maintenance import MaintenanceTask

DISCORD_URL = "https://discord.com/api/webhooks/123/tok-SUPERSECRET"


class FakeTransport:
    """Records outbound requests and always succeeds."""

    def __init__(self) -> None:
        self.requests: list[object] = []

    async def __call__(self, request: object) -> DeliveryResult:
        self.requests.append(request)
        return DeliveryResult(ok=True, status_code=204)


def make_event(
    summary: str = "Gateway MAC changed",
    *,
    severity: Severity = Severity.HIGH,
    ts: datetime | None = None,
) -> Event:
    fields: dict[str, object] = {
        "type": EventType.ARP_SPOOF,
        "severity": severity,
        "detector": "arp",
        "summary": summary,
        "src_mac": "de:ad:be:ef:00:01",
        "src_ip": "10.0.0.2",
    }
    if ts is not None:
        fields["ts"] = ts
    return Event(**fields)  # type: ignore[arg-type]


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    yield database
    database.close()


def make_service(
    db: Database,
    published: list[Event],
    transport: FakeTransport | None = None,
) -> DeliveryService:
    """A delivery service whose publish sink is a plain list."""

    async def publish(event: Event) -> None:
        published.append(event)

    transports = {ChannelKind.DISCORD: transport} if transport is not None else None
    return DeliveryService(db, ChannelStore(db), publish, transports=transports)


def test_first_poll_does_not_replay_rows_that_predate_delivery(db: Database) -> None:
    """Installing this version must not alert on the entire historical database."""
    db.insert_event(make_event("old event from before the upgrade"))
    published: list[Event] = []
    service = make_service(db, published)

    assert asyncio.run(service.poll_once()) == 0
    assert published == []


def test_a_new_event_is_published_once(db: Database) -> None:
    published: list[Event] = []
    service = make_service(db, published)

    asyncio.run(service.poll_once())
    stored = db.insert_event(make_event("gateway changed"))

    assert asyncio.run(service.poll_once()) == 1
    assert [event.id for event in published] == [stored.id]
    # Polling again is a no-op: the cursor has moved.
    assert asyncio.run(service.poll_once()) == 0
    assert len(published) == 1


def test_delivery_resumes_after_a_restart(db: Database) -> None:
    """An event stored while the web process was down is delivered on its return."""
    first_published: list[Event] = []
    make_service(db, first_published)
    asyncio.run(make_service(db, first_published).poll_once())

    stored = db.insert_event(make_event("arrived while the web was down"))

    second_published: list[Event] = []
    second = make_service(db, second_published)
    assert asyncio.run(second.poll_once()) == 1
    assert [event.id for event in second_published] == [stored.id]


def test_enabled_channel_receives_a_message(db: Database) -> None:
    channels = ChannelStore(db)
    channels.save(
        ChannelKind.DISCORD,
        fields={"webhook_url": DISCORD_URL},
        min_severity=Severity.MEDIUM,
    )
    transport = FakeTransport()
    published: list[Event] = []

    async def publish(event: Event) -> None:
        published.append(event)

    service = DeliveryService(db, channels, publish, transports={ChannelKind.DISCORD: transport})

    async def scenario() -> int:
        await service.poll_once()
        db.insert_event(make_event("gateway changed"))
        processed = await service.poll_once()
        await service.stop()  # drains the notifier before the assertions
        return processed

    assert asyncio.run(scenario()) == 1
    assert len(transport.requests) == 1
    request = transport.requests[0]
    assert isinstance(request, HttpRequest)
    assert "gateway changed" in str(request.json.get("content", ""))


def test_a_channel_below_its_minimum_severity_is_not_messaged(db: Database) -> None:
    channels = ChannelStore(db)
    channels.save(
        ChannelKind.DISCORD,
        fields={"webhook_url": DISCORD_URL},
        min_severity=Severity.CRITICAL,
    )
    transport = FakeTransport()
    published: list[Event] = []

    async def publish(event: Event) -> None:
        published.append(event)

    service = DeliveryService(db, channels, publish, transports={ChannelKind.DISCORD: transport})

    async def scenario() -> None:
        await service.poll_once()
        db.insert_event(make_event("only medium", severity=Severity.MEDIUM))
        await service.poll_once()
        await service.stop()

    asyncio.run(scenario())
    # The feed still shows it; the channel was told to stay quiet for it.
    assert len(published) == 1
    assert transport.requests == []


def test_run_stops_when_the_stop_event_is_set(db: Database) -> None:
    published: list[Event] = []
    service = make_service(db, published)

    async def scenario() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(service.run(stop))
        await asyncio.sleep(0.05)
        db.insert_event(make_event("seen by the loop"))
        for _ in range(50):
            if published:
                break
            await asyncio.sleep(0.05)
        stop.set()
        await asyncio.wait_for(task, timeout=2.0)

    asyncio.run(scenario())
    assert [event.summary for event in published] == ["seen by the loop"]


# --- retention ----------------------------------------------------------------


def test_maintenance_prunes_events_past_retention(db: Database) -> None:
    now = datetime.now(UTC).timestamp()
    old = datetime.fromtimestamp(now - 10 * 86_400.0, UTC)
    db.insert_event(make_event("old", ts=old))
    fresh = db.insert_event(make_event("fresh"))
    preferences = PreferencesStore(db)
    preferences.update(retention_days=1)

    task = MaintenanceTask(db, preferences, clock=lambda: now)
    removed = task.run_once()

    assert removed["events"] == 1
    remaining = [event.id for event in db.list_events()]
    assert remaining == [fresh.id]


def test_retention_never_deletes_an_undelivered_event(db: Database) -> None:
    """Delivery is at-least-once, so an unseen alert outranks the storage bound."""
    now = datetime.now(UTC).timestamp()
    old = datetime.fromtimestamp(now - 10 * 86_400.0, UTC)
    db.insert_event(make_event("old but undelivered", ts=old))
    preferences = PreferencesStore(db)
    preferences.update(retention_days=1)

    task = MaintenanceTask(db, preferences, clock=lambda: now)
    removed = task.run_once(delivered_rowid=0)

    assert removed["events"] == 0
    assert len(db.list_events()) == 1


def test_maintenance_prunes_stale_login_attempts(db: Database) -> None:
    now = 1_700_000_000.0
    db.record_login_attempt("client:10.0.0.66", now - 8 * 86_400.0, False)
    db.record_login_attempt("client:10.0.0.66", now - 60.0, False)

    task = MaintenanceTask(db, PreferencesStore(db), clock=lambda: now)
    removed = task.run_once()

    assert removed["login_attempts"] == 1
    assert db.failed_attempts_since("client:10.0.0.66", 0.0) == 1


def test_delivery_cursor_is_durable(db: Database) -> None:
    db.insert_event(make_event("first"))
    published: list[Event] = []
    service = make_service(db, published)
    asyncio.run(service.poll_once())

    assert db.get_setting(CURSOR_KEY) == str(service.cursor)
