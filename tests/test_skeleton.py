"""M1 walking-skeleton acceptance tests.

Desired behaviour:
  * a normalized ``Event`` round-trips through SQLite (WAL);
  * an event stored the way the sensor stores it is served by the web app;
  * the dashboard page renders stored events;
  * the web app itself creates no events — detection belongs to the sensor process.

These tests ran red until the modules existed; they now guard the behaviour.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.web.app import create_app

#: Long enough to satisfy the password policy in the first-run wizard.
ADMIN_PASSWORD = "a perfectly long passphrase"


def _complete_setup(client: TestClient) -> None:
    """Run the first-run wizard (including its setup token) as a console owner would."""
    auth = cast(FastAPI, client.app).state.auth
    token = auth.ensure_setup_token()
    assert token is not None
    response = client.post(
        "/setup",
        data={"username": "admin", "password": ADMIN_PASSWORD, "setup_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303


def _store_event(app: FastAPI, summary: str = "hello gilgamesh") -> Event:
    """Insert an event the way the sensor process does: straight into SQLite."""
    database = app.state.db
    return database.insert_event(
        Event(
            type=EventType.ARP_SPOOF,
            severity=Severity.HIGH,
            detector="arp",
            summary=summary,
            src_mac="de:ad:be:ef:00:01",
            src_ip="10.0.0.2",
        )
    )


def test_event_roundtrips_through_database(tmp_path: Path) -> None:
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()

    event = Event(
        type=EventType.TEST,
        severity=Severity.INFO,
        detector="pipette",
        summary="hello gilgamesh",
    )
    stored = db.insert_event(event)

    assert stored.id == event.id
    events = db.list_events()
    assert len(events) == 1
    assert events[0].summary == "hello gilgamesh"
    assert events[0].detector == "pipette"

    assert db.get_event(event.id) == events[0]
    db.close()


def test_web_startup_does_not_invent_events(tmp_path: Path) -> None:
    """An empty install shows an empty feed; detection is the sensor's job, not the web's."""
    app = create_app(Settings(data_dir=tmp_path))

    with TestClient(app) as client:
        _complete_setup(client)
        response = client.get("/api/events")

    assert response.status_code == 200
    assert response.json() == []


def test_stored_event_is_served_by_api(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path))

    with TestClient(app) as client:
        _complete_setup(client)
        _store_event(app)
        response = client.get("/api/events")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["detector"] == "arp"
    assert payload[0]["summary"] == "hello gilgamesh"


def test_dashboard_renders_stored_events(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path))

    with TestClient(app) as client:
        _complete_setup(client)
        _store_event(app, summary="an event from the sensor")
        response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "an event from the sensor" in response.text


def test_healthz_needs_no_login(tmp_path: Path) -> None:
    """The liveness probe must stay reachable without credentials."""
    app = create_app(Settings(data_dir=tmp_path))

    with TestClient(app) as client:
        response = client.get("/api/healthz")

    assert response.status_code == 200
