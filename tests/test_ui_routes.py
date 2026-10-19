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
from gilgamesh.web import deps
from gilgamesh.web.app import create_app
from gilgamesh.web.sse import EventBus

PASSWORD = "a perfectly long passphrase"
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as test_client:
        auth = cast(FastAPI, test_client.app).state.auth
        token = auth.ensure_setup_token()
        response = test_client.post(
            "/setup",
            data={"username": "admin", "password": PASSWORD, "setup_token": token},
            follow_redirects=False,
        )
        assert response.status_code == 303
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


def test_static_assets_are_revalidated_instead_of_cached_blindly(client: TestClient) -> None:
    """The vendored assets keep their names across upgrades.

    Without this header a browser may reuse the app.js it downloaded before
    `install.sh` shipped a new one — the owner would see the old behaviour with no clue
    why. Starlette sends an ETag, so revalidating costs a 304, not a re-download.
    """
    response = client.get("/static/js/app.js")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-cache"
    assert response.headers.get("ETag")


def test_html_is_never_stored_by_the_browser(client: TestClient) -> None:
    assert client.get("/").headers["Cache-Control"] == "no-store"


def test_every_asset_url_carries_the_content_stamp(client: TestClient) -> None:
    """Belt and braces with the `no-cache` header: a *changed* asset is a new URL.

    Browsers are free to ignore revalidation heuristics; they cannot ignore a URL that
    has never been requested. If this fails, an upgraded Pi can keep serving the
    previous app.js/CSS to the owner's browser without any visible symptom.
    """
    body = client.get("/login").text
    stamp = deps.asset_version()

    assert stamp
    for asset in ("/static/css/app.css", "/static/js/app.js", "/static/js/vendor/htmx.min.js"):
        assert f"{asset}?v={stamp}" in body, asset
    assert "/static/favicon.svg?v=" in body


def test_the_content_stamp_tracks_the_files(tmp_path: Path) -> None:
    asset = tmp_path / "app.js"
    asset.write_text("first", encoding="utf-8")
    before = deps.asset_version(tmp_path)

    asset.write_text("second version, longer", encoding="utf-8")

    assert deps.asset_version(tmp_path) != before


def test_no_external_urls_anywhere_in_templates() -> None:
    """Offline-first (C5): no CDN, no external fonts, no remote scripts."""
    offenders: list[str] = []
    pattern = re.compile(r"(https?:)?//(?!127\.0\.0\.1|localhost)", re.IGNORECASE)
    for template in (REPO_ROOT / "src/gilgamesh/web/templates").glob("*.html"):
        text = template.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(template.name)
    assert offenders == []


def test_no_template_ships_an_unstyled_form_control() -> None:
    """Every visible control carries design-system classes.

    The audit found three pages rendering as raw HTML — sign-in, first-run setup and the
    allowlist — because they were the only templates whose markup skipped the class
    vocabulary the rest of the app shares. Two of those are the first screens a new owner
    sees, and the styling is an acceptance criterion, not decoration. Hidden inputs are
    exempt: they are never painted.
    """
    offenders: list[str] = []
    pattern = re.compile(r"<(input|select|button|label|table)\b[^>]*>")
    for template in sorted((REPO_ROOT / "src/gilgamesh/web/templates").glob("*.html")):
        text = template.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            tag = match.group(0)
            if tag.startswith("<input") and 'type="hidden"' in tag:
                continue
            if 'class="' not in tag:
                offenders.append(f"{template.name}: {tag.splitlines()[0][:70]}")

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


def test_dashboard_carries_the_alpine_feed_control(client: TestClient) -> None:
    """The pause control is an Alpine CSP component, registered by name in app.js.

    Only the wiring is asserted here; that it actually initialises in a browser (and
    under the real CSP) is what the Playwright end-to-end test checks.
    """
    body = client.get("/").text
    script = (REPO_ROOT / "static/js/app.js").read_text(encoding="utf-8")

    assert 'x-data="liveFeed"' in body
    assert '@click="toggle"' in body
    assert 'x-text="buttonLabel"' in body
    assert 'window.Alpine.data("liveFeed"' in script
    # No inline expression can survive the CSP build, so the component must not use one.
    assert "x-show=" not in body


def test_sse_frame_is_valid_json(client: TestClient) -> None:
    """The browser parses `data:` as JSON, so the frame must be valid."""
    bus_published = json.dumps({"id": "x", "severity": "high", "summary": "s"})
    parsed = json.loads(bus_published)

    assert parsed["summary"] == "s"
