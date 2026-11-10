"""Device behaviour summaries and the device-detail page.

The Devices list is the owner's entry point into behaviour detection: it has to say
whether a device is still learning, calibrated, or not tracked at all. The detail
page then explains the numbers behind that label. These tests exercise the store
queries and the HTTP surface together, because the page is only useful if both agree.
"""

from __future__ import annotations

import math
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gilgamesh.behaviour.store import (
    ActivityBucket,
    BaselineRow,
    BehaviourStore,
)
from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.web.app import create_app

PASSWORD = "a perfectly long passphrase"
MAC = "aa:bb:cc:dd:ee:01"
OTHER = "aa:bb:cc:dd:ee:02"
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def store(database: Database) -> BehaviourStore:
    return BehaviourStore(database)


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


def _state(client: TestClient) -> FastAPI:
    return cast(FastAPI, client.app)


def _seed_device(
    client: TestClient,
    *,
    mac: str = MAC,
    hostname: str | None = "Camera",
    vendor: str | None = "Acme",
) -> None:
    DeviceStore(_state(client).state.db).upsert(
        mac,
        ip="10.0.0.5",
        hostname=hostname,
        vendor=vendor,
        seen_ts=datetime.now(UTC),
    )


def _seed_baseline(
    store: BehaviourStore,
    *,
    mac: str = MAC,
    samples: int = 10,
    days_ago: int = 3,
    metric: str = "bytes_out_log",
    mean: float | None = None,
) -> None:
    now = datetime.now(UTC)
    store.upsert_baseline(
        BaselineRow(
            device_mac=mac,
            metric=metric,
            mean=math.log1p(2000) if mean is None else mean,
            variance=0.1,
            samples=samples,
            learning_started_ts=now - timedelta(days=days_ago, hours=1),
            updated_ts=now,
        )
    )


# --- store queries ------------------------------------------------------------


def test_summaries_label_learning_and_calibrated_devices(store: BehaviourStore) -> None:
    store.upsert_baseline(
        BaselineRow(
            device_mac=MAC,
            metric="bytes_out_log",
            mean=math.log1p(2000),
            variance=0.1,
            samples=10,
            learning_started_ts=NOW - timedelta(days=3),
            updated_ts=NOW,
        )
    )

    summary = store.summaries(now=NOW, calibration_days=7)[MAC]

    assert summary.state == "learning"
    assert summary.days_learning == 3
    assert summary.samples == 10
    assert summary.calibration_days == 7

    store.upsert_baseline(
        BaselineRow(
            device_mac=MAC,
            metric="bytes_out_log",
            mean=math.log1p(2000),
            variance=0.1,
            samples=30,
            learning_started_ts=NOW - timedelta(days=8),
            updated_ts=NOW,
        )
    )

    summary = store.summaries(now=NOW, calibration_days=7)[MAC]

    assert summary.state == "calibrated"
    assert summary.days_learning == 7


def test_summaries_use_bytes_out_log_and_skip_devices_without_one(
    store: BehaviourStore,
) -> None:
    store.upsert_baseline(
        BaselineRow(
            device_mac=MAC,
            metric="bytes_out_log",
            mean=1.0,
            variance=0.0,
            samples=10,
            learning_started_ts=NOW - timedelta(days=2),
            updated_ts=NOW,
        )
    )
    store.upsert_baseline(
        BaselineRow(
            device_mac=MAC,
            metric="bytes_in_log",
            mean=1.0,
            variance=0.0,
            samples=50,
            learning_started_ts=NOW - timedelta(days=9),
            updated_ts=NOW,
        )
    )
    store.upsert_baseline(
        BaselineRow(
            device_mac=OTHER,
            metric="unique_dst",
            mean=1.0,
            variance=0.0,
            samples=50,
            learning_started_ts=NOW - timedelta(days=9),
            updated_ts=NOW,
        )
    )

    summaries = store.summaries(now=NOW, calibration_days=7)

    assert summaries[MAC].samples == 10
    assert summaries[MAC].state == "learning"
    assert OTHER not in summaries


def test_zero_day_calibration_needs_twenty_samples(store: BehaviourStore) -> None:
    store.upsert_baseline(
        BaselineRow(
            device_mac=MAC,
            metric="bytes_out_log",
            mean=1.0,
            variance=0.0,
            samples=10,
            learning_started_ts=NOW,
            updated_ts=NOW,
        )
    )

    assert store.summaries(now=NOW, calibration_days=0)[MAC].state == "learning"

    store.upsert_baseline(
        BaselineRow(
            device_mac=MAC,
            metric="bytes_out_log",
            mean=1.0,
            variance=0.0,
            samples=20,
            learning_started_ts=NOW,
            updated_ts=NOW,
        )
    )

    assert store.summaries(now=NOW, calibration_days=0)[MAC].state == "calibrated"


def test_device_profile_reads_recent_buckets_baselines_and_events(
    store: BehaviourStore, database: Database
) -> None:
    store.write_bucket(ActivityBucket(MAC, NOW - timedelta(hours=1), bytes_out=1000))
    store.write_bucket(ActivityBucket(MAC, NOW - timedelta(hours=25), bytes_out=9000))
    store.upsert_baseline(
        BaselineRow(
            device_mac=MAC,
            metric="bytes_out_log",
            mean=1.0,
            variance=0.0,
            samples=10,
            learning_started_ts=NOW - timedelta(days=2),
            updated_ts=NOW,
        )
    )
    store.upsert_baseline(
        BaselineRow(
            device_mac=OTHER,
            metric="bytes_out_log",
            mean=1.0,
            variance=0.0,
            samples=10,
            learning_started_ts=NOW - timedelta(days=2),
            updated_ts=NOW,
        )
    )
    database.insert_event(
        Event(
            ts=NOW - timedelta(minutes=2),
            type=EventType.BEHAVIOUR_ANOMALY,
            severity=Severity.MEDIUM,
            detector="behaviour.volume_spike",
            summary="Camera uploaded far more than usual",
            src_mac=MAC,
        )
    )
    database.insert_event(
        Event(
            ts=NOW - timedelta(minutes=1),
            type=EventType.PORT_SCAN,
            severity=Severity.LOW,
            detector="scan",
            summary="Inbound probe",
            dst_mac=MAC,
        )
    )
    database.insert_event(
        Event(
            ts=NOW,
            type=EventType.PORT_SCAN,
            severity=Severity.LOW,
            detector="scan",
            summary="Other device event",
            src_mac=OTHER,
        )
    )

    profile = store.device_profile(MAC, now=NOW, calibration_days=7)

    assert [bucket.bytes_out for bucket in profile.buckets] == [1000]
    assert [row.device_mac for row in profile.baselines] == [MAC]
    assert [event.summary for event in profile.recent_events] == [
        "Inbound probe",
        "Camera uploaded far more than usual",
    ]


def test_new_destinations_since_counts_first_sightings(
    store: BehaviourStore,
) -> None:
    store.record_destinations(MAC, ["192.0.2.1"], seen_ts=NOW - timedelta(hours=2))
    store.record_destinations(MAC, ["192.0.2.2"], seen_ts=NOW - timedelta(days=2))
    store.record_destinations(OTHER, ["192.0.2.3"], seen_ts=NOW - timedelta(hours=1))

    assert store.new_destinations_since(MAC, since=NOW - timedelta(hours=24)) == 1


# --- the devices list ---------------------------------------------------------


def test_devices_list_has_a_behaviour_column(client: TestClient) -> None:
    _seed_device(client)
    _seed_baseline(BehaviourStore(_state(client).state.db))

    body = client.get("/devices").text

    assert "Behaviour" in body
    assert "learning (3/7 days)" in body
    assert f'href="/devices/{MAC}"' in body


def test_devices_list_says_disabled_when_behaviour_is_off(client: TestClient) -> None:
    _seed_device(client)
    _seed_baseline(BehaviourStore(_state(client).state.db))
    _state(client).state.preferences.update(behaviour_enabled=False)

    body = client.get("/devices").text

    assert "disabled" in body


# --- the detail page ----------------------------------------------------------


def test_device_detail_renders_profile_and_404s_unknown_mac(client: TestClient) -> None:
    _seed_device(client)
    behaviour = BehaviourStore(_state(client).state.db)
    _seed_baseline(behaviour)
    behaviour.write_bucket(
        ActivityBucket(
            MAC,
            datetime.now(UTC) - timedelta(minutes=30),
            bytes_in=500,
            bytes_out=1000,
            unique_dst=2,
            dns_queries=3,
        )
    )

    response = client.get(f"/devices/{MAC}")

    assert response.status_code == 200
    assert MAC in response.text
    assert "Normal vs last 24 hours" in response.text
    assert "learning (3/7 days)" in response.text
    assert "10 samples" in response.text
    assert client.get("/devices/aa:bb:cc:dd:ee:ff").status_code == 404


def test_device_detail_has_an_inline_svg_and_no_chart_library(client: TestClient) -> None:
    _seed_device(client)
    BehaviourStore(_state(client).state.db).write_bucket(
        ActivityBucket(MAC, datetime.now(UTC) - timedelta(minutes=30), bytes_out=1000)
    )

    body = client.get(f"/devices/{MAC}").text

    assert "<svg" in body
    assert "polyline" in body
    assert "<title>" in body
    assert "cdn." not in body


def test_device_detail_lists_recent_events_for_the_device(client: TestClient) -> None:
    _seed_device(client)
    database = _state(client).state.db
    database.insert_event(
        Event(
            ts=datetime.now(UTC),
            type=EventType.BEHAVIOUR_ANOMALY,
            severity=Severity.MEDIUM,
            detector="behaviour.volume_spike",
            summary="Suspicious upload",
            src_mac=MAC,
        )
    )
    database.insert_event(
        Event(
            ts=datetime.now(UTC),
            type=EventType.PORT_SCAN,
            severity=Severity.LOW,
            detector="scan",
            summary="Inbound probe",
            dst_mac=MAC,
        )
    )
    database.insert_event(
        Event(
            ts=datetime.now(UTC),
            type=EventType.PORT_SCAN,
            severity=Severity.LOW,
            detector="scan",
            summary="Other device event",
            src_mac=OTHER,
        )
    )

    body = client.get(f"/devices/{MAC}").text

    assert "Suspicious upload" in body
    assert "Inbound probe" in body
    assert "Other device event" not in body


def test_device_detail_says_disabled_when_behaviour_is_off(client: TestClient) -> None:
    _seed_device(client)
    _seed_baseline(BehaviourStore(_state(client).state.db))
    _state(client).state.preferences.update(behaviour_enabled=False)

    body = client.get(f"/devices/{MAC}").text

    assert "disabled" in body
