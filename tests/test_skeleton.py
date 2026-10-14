"""M1 walking-skeleton acceptance tests.

Desired behaviour:
  * a normalized ``Event`` round-trips through SQLite (WAL);
  * the fake detector produces one event that is stored and served by the web app;
  * the dashboard page renders stored events.

These tests fail until the modules exist — that is the point (TDD red step).
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.web.app import create_app

#: Long enough to satisfy the password policy in the first-run wizard.
ADMIN_PASSWORD = "a perfectly long passphrase"


def _complete_setup(client: TestClient) -> None:
    """Run the first-run wizard so the client holds an administrator session."""
    response = client.post(
        "/setup", data={"username": "admin", "password": ADMIN_PASSWORD}, follow_redirects=False
    )
    assert response.status_code == 303


def test_event_roundtrips_through_database(tmp_path: Path) -> None:
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()

    event = Event(
        type=EventType.TEST,
        severity=Severity.INFO,
        detector="fake",
        summary="hello gilgamesh",
    )
    stored = db.insert_event(event)

    assert stored.id == event.id
    events = db.list_events()
    assert len(events) == 1
    assert events[0].summary == "hello gilgamesh"
    assert events[0].detector == "fake"

    assert db.get_event(event.id) == events[0]
    db.close()


def test_fake_detector_event_is_served_by_api(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path))

    with TestClient(app) as client:
        _complete_setup(client)
        response = client.get("/api/events")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["detector"] == "fake"
    assert payload[0]["type"] == "test"


def test_dashboard_renders_stored_events(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path))

    with TestClient(app) as client:
        _complete_setup(client)
        response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "hello gilgamesh" in response.text


def test_healthz_needs_no_login(tmp_path: Path) -> None:
    """The liveness probe must stay reachable without credentials."""
    app = create_app(Settings(data_dir=tmp_path))

    with TestClient(app) as client:
        response = client.get("/api/healthz")

    assert response.status_code == 200
