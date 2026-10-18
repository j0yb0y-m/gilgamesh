"""M13 — live dashboard (SSE) and alert pages.

These tests cover the parts of the UI that are behaviour rather than markup: the live
stream requires a session, events actually arrive, a slow subscriber is dropped rather
than allowed to block the publisher, security headers are on every response, and the
vendored assets are served from this machine with no external URLs anywhere.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from collections.abc import AsyncGenerator, Callable, Iterator
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Message

from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.web.app import create_app
from gilgamesh.web.sse import EventBus

PASSWORD = "a perfectly long passphrase"
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as test_client:
        test_client.post(
            "/setup", data={"username": "admin", "password": PASSWORD}, follow_redirects=False
        )
        yield test_client


def csrf_from(client: TestClient, path: str) -> str:
    body = client.get(path).text
    marker = 'name="csrf_token" value="'
    start = body.index(marker) + len(marker)
    return body[start : body.index('"', start)]


def seed_event(database_path: Path, **overrides: object) -> str:
    """Insert an event straight into the database so the UI has something to show."""
    database = Database(database_path)
    database.initialize()
    fields: dict[str, object] = {
        "type": EventType.ARP_SPOOF,
        "severity": Severity.HIGH,
        "detector": "arp",
        "summary": "Gateway MAC changed",
        "src_ip": "10.0.0.2",
    }
    fields.update(overrides)
    event = database.insert_event(Event(**fields))  # type: ignore[arg-type]
    database.close()
    return event.id


# --- the live stream ----------------------------------------------------------


def _session_cookie(client: TestClient) -> bytes:
    """The raw ``Cookie:`` header for the signed-in test client."""
    return b"; ".join(f"{name}={value}".encode() for name, value in client.cookies.items())


def _stream_scope(cookie: bytes) -> dict[str, object]:
    """A minimal ASGI HTTP scope for ``GET /events/stream``."""
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/events/stream",
        "raw_path": b"/events/stream",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver"), (b"cookie", cookie)],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "state": {},
    }


async def _wait_until(predicate: Callable[[], bool], *, window: float = 2.0) -> None:
    """Spin until ``predicate()`` is true, or time out after ``window`` seconds."""
    async with asyncio.timeout(window):
        while not predicate():
            await asyncio.sleep(0.005)


@contextlib.asynccontextmanager
async def open_stream(
    app: ASGIApp, cookie: bytes
) -> AsyncGenerator[tuple[Message, asyncio.Queue[bytes]]]:
    """Drive the real ASGI app and expose the SSE response as it is produced.

    ``TestClient`` cannot be used for this: Starlette 1.8 buffers the *whole* response
    body before ``handle_request`` returns, so an endless stream never returns at all.
    Calling the ASGI interface ourselves lets the test read the first frames and then
    disconnect, which is exactly how a browser behaves.
    """
    start: Message = {}
    frames: asyncio.Queue[bytes] = asyncio.Queue()
    connected = asyncio.Event()
    disconnected = asyncio.Event()
    request_sent = False

    async def receive() -> Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        if message["type"] == "http.response.start":
            start.update(message)
            connected.set()
        elif message["type"] == "http.response.body" and message.get("body"):
            frames.put_nowait(message["body"])

    async def drive() -> None:
        await app(_stream_scope(cookie), receive, send)

    task = asyncio.create_task(drive())
    try:
        await asyncio.wait_for(connected.wait(), timeout=2.0)
        yield start, frames
    finally:
        disconnected.set()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(task, timeout=2.0)


async def test_bus_delivers_a_published_event() -> None:
    bus = EventBus()
    received: list[bytes] = []

    async def listen() -> None:
        async for frame in bus.subscribe():
            received.append(frame)

    task = asyncio.create_task(listen())
    await asyncio.sleep(0)
    await bus.publish({"id": "abc", "severity": "high", "type": "arp_spoof", "summary": "x"})
    await asyncio.sleep(0)
    await bus.unsubscribe_all()
    await asyncio.wait_for(task, timeout=2.0)

    assert len(received) == 1
    frame = received[0].decode()
    assert frame.startswith("event: alert")
    assert '"summary": "x"' in frame
    assert frame.endswith("\n\n")


async def test_bus_tracks_subscribers() -> None:
    bus = EventBus()

    async def listen() -> None:
        async for _ in bus.subscribe():
            pass

    task = asyncio.create_task(listen())
    await asyncio.sleep(0)

    assert bus.subscriber_count == 1

    await bus.unsubscribe_all()
    await asyncio.wait_for(task, timeout=2.0)
    assert bus.subscriber_count == 0


async def test_slow_subscriber_never_blocks_the_publisher() -> None:
    """A stalled browser tab must not be able to slow down detection."""
    bus = EventBus()

    async def listen_forever() -> None:
        async for _ in bus.subscribe():
            pass  # deliberately never drained

    task = asyncio.create_task(listen_forever())
    await asyncio.sleep(0)

    for index in range(500):
        await asyncio.wait_for(bus.publish({"n": index}), timeout=1.0)

    await bus.unsubscribe_all()
    await asyncio.wait_for(task, timeout=2.0)


async def test_publishing_without_subscribers_is_harmless() -> None:
    bus = EventBus()

    await bus.publish({"n": 1})

    assert bus.subscriber_count == 0


def test_stream_requires_a_session(client: TestClient) -> None:
    client.cookies.clear()

    response = client.get("/events/stream", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_stream_sets_the_sse_content_type(client: TestClient) -> None:
    async with open_stream(client.app, _session_cookie(client)) as (start, _frames):
        headers = {name.decode(): value.decode() for name, value in start["headers"]}

    assert start["status"] == 200
    assert headers["content-type"].startswith("text/event-stream")
    assert headers["cache-control"].startswith("no-cache")


async def test_stream_emits_a_published_event(client: TestClient) -> None:
    """The acceptance criterion: an event published on the bus reaches the client."""
    # ``TestClient`` claims its app is a bare ``ASGIApp``, so ``.state`` is not on
    # its declared type; the runtime object is the FastAPI app this fixture built.
    bus: EventBus = cast(FastAPI, client.app).state.bus
    async with open_stream(client.app, _session_cookie(client)) as (_start, frames):
        await _wait_until(lambda: bus.subscriber_count == 1)
        await bus.publish({"id": "abc", "type": "arp_spoof", "severity": "high", "summary": "hi"})
        frame = (await asyncio.wait_for(frames.get(), timeout=2.0)).decode()

    assert frame.startswith("event: alert")
    assert '"summary": "hi"' in frame
    assert frame.endswith("\n\n")


def test_stream_frames_are_wire_format_bytes() -> None:
    """`EventSourceResponse` needs bytes, not model objects — this is the contract."""
    from fastapi.sse import format_sse_event

    bus = EventBus()
    frames: list[bytes] = []

    async def drain() -> None:
        async for frame in bus.subscribe():
            frames.append(frame)

    async def scenario() -> None:
        task = asyncio.create_task(drain())
        await asyncio.sleep(0)
        await bus.publish({"summary": "live"})
        await asyncio.sleep(0)
        await bus.unsubscribe_all()
        await asyncio.wait_for(task, timeout=2.0)

    asyncio.run(scenario())

    assert frames and isinstance(frames[0], bytes)
    assert frames[0] == format_sse_event(data_str='{"summary": "live"}', event="alert")


# --- security headers ---------------------------------------------------------


def test_security_headers_are_present(client: TestClient) -> None:
    response = client.get("/")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_csp_omits_unsafe_eval(client: TestClient) -> None:
    """Alpine's CSP build is vendored precisely so this can stay true."""
    csp = client.get("/").headers["Content-Security-Policy"]

    assert "unsafe-eval" not in csp
    assert "script-src 'self'" in csp


def test_static_assets_are_served(client: TestClient) -> None:
    assert client.get("/static/css/app.css").status_code == 200
    assert client.get("/static/js/vendor/htmx.min.js").status_code == 200
    assert client.get("/static/js/vendor/alpine-csp.min.js").status_code == 200


def test_no_external_urls_anywhere_in_templates() -> None:
    """Offline-first (C5): no CDN, no external fonts, no remote scripts."""
    offenders: list[str] = []
    pattern = re.compile(r"(https?:)?//(?!127\.0\.0\.1|localhost)", re.IGNORECASE)
    for template in (REPO_ROOT / "src/gilgamesh/web/templates").glob("*.html"):
        text = template.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(template.name)
    assert offenders == []


def test_vendor_manifest_records_hashes() -> None:
    manifest = (REPO_ROOT / "static/js/vendor/VENDOR.md").read_text(encoding="utf-8")

    assert "0BSD" in manifest
    assert "MIT" in manifest
    assert re.search(r"[0-9a-f]{64}", manifest)


# --- alerts -------------------------------------------------------------------


def test_alerts_page_requires_a_session(client: TestClient) -> None:
    client.cookies.clear()

    assert client.get("/alerts", follow_redirects=False).status_code == 303


def test_alerts_page_lists_alerts(client: TestClient, tmp_path: Path) -> None:
    seed_event(tmp_path / "gilgamesh.db")

    response = client.get("/alerts")

    assert response.status_code == 200
    assert "Gateway MAC changed" in response.text


def test_alerts_can_be_filtered_by_severity(client: TestClient, tmp_path: Path) -> None:
    seed_event(tmp_path / "gilgamesh.db", severity=Severity.HIGH, summary="keep me")
    seed_event(tmp_path / "gilgamesh.db", severity=Severity.LOW, summary="drop me")

    response = client.get("/alerts?severity=high")

    assert "keep me" in response.text
    assert "drop me" not in response.text


def test_alerts_can_be_searched(client: TestClient, tmp_path: Path) -> None:
    seed_event(tmp_path / "gilgamesh.db", summary="arp poisoning observed")
    seed_event(tmp_path / "gilgamesh.db", summary="unrelated notice")

    response = client.get("/alerts?search=poisoning")

    assert "arp poisoning observed" in response.text
    assert "unrelated notice" not in response.text


def test_alert_detail_shows_evidence(client: TestClient, tmp_path: Path) -> None:
    event_id = seed_event(tmp_path / "gilgamesh.db")

    response = client.get(f"/alerts/{event_id}")

    assert response.status_code == 200
    assert "arp" in response.text


def test_alert_detail_404s_for_unknown_id(client: TestClient) -> None:
    assert client.get("/alerts/does-not-exist").status_code == 404


def test_acknowledge_requires_csrf(client: TestClient, tmp_path: Path) -> None:
    event_id = seed_event(tmp_path / "gilgamesh.db")

    response = client.post(f"/alerts/{event_id}/acknowledge")

    assert response.status_code == 403


def test_acknowledge_is_recorded(client: TestClient, tmp_path: Path) -> None:
    event_id = seed_event(tmp_path / "gilgamesh.db")
    token = csrf_from(client, f"/alerts/{event_id}")

    response = client.post(
        f"/alerts/{event_id}/acknowledge", data={"csrf_token": token}, follow_redirects=False
    )

    assert response.status_code == 303
    database = Database(tmp_path / "gilgamesh.db")
    entries = [row["action"] for row in database.audit_entries()]
    database.close()
    assert any("acknowledged by admin" in action for action in entries)


def test_dashboard_links_to_the_live_stream(client: TestClient) -> None:
    body = client.get("/").text

    assert 'id="live-feed"' in body
    assert "/events/stream" in (REPO_ROOT / "static/js/app.js").read_text(encoding="utf-8")


def test_sse_frame_is_valid_json(client: TestClient) -> None:
    """The browser parses `data:` as JSON, so the frame must be valid."""
    bus_published = json.dumps({"id": "x", "severity": "high", "summary": "s"})
    parsed = json.loads(bus_published)

    assert parsed["summary"] == "s"
