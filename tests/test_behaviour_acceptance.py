"""Acceptance: a day of benign traffic stays quiet; the attack fixture is caught.

The fixtures are real Suricata 8 EVE JSONL, replayed through the production
aggregator with ``calibration_days=0`` (the documented lab/demo mode). The
20-sample gate is not bypassed, and the attack replay seeds its baselines from
the benign day first, exactly as a real sensor would have done.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from gilgamesh.behaviour.aggregate import BehaviourAggregator
from gilgamesh.behaviour.attribution import DeviceMap
from gilgamesh.behaviour.eve import DnsFact, FlowFact, parse_behaviour_record
from gilgamesh.behaviour.store import BehaviourStore
from gilgamesh.db import Database
from gilgamesh.devices import DeviceRecord
from gilgamesh.models import Event, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "behaviour"

DEVICES = (
    ("aa:bb:cc:00:00:01", "10.0.0.10", "Camera"),
    ("aa:bb:cc:00:00:02", "10.0.0.11", "Phone"),
    ("aa:bb:cc:00:00:03", "10.0.0.12", "Laptop"),
    ("aa:bb:cc:00:00:04", "10.0.0.13", "TV"),
    ("aa:bb:cc:00:00:05", "10.0.0.14", "Thermostat"),
)


def _load(name: str) -> list[dict[str, object]]:
    lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
    return [cast("dict[str, object]", json.loads(line)) for line in lines if line.strip()]


def _device_map() -> DeviceMap:
    moment = datetime(2026, 11, 1, tzinfo=UTC)
    devices = DeviceMap()
    devices.refresh(
        [
            DeviceRecord(mac=mac, ips=(ip,), hostname=label, first_ts=moment, last_ts=moment)
            for mac, ip, label in DEVICES
        ]
    )
    return devices


def _floor(moment: datetime) -> datetime:
    epoch = int(moment.timestamp())
    return datetime.fromtimestamp(epoch - epoch % 900, UTC)


def _feed(aggregator: BehaviourAggregator, records: Iterable[dict[str, object]]) -> list[Event]:
    """Replay records in bucket order, flushing each bucket at its end."""
    events: list[Event] = []
    bucket: datetime | None = None
    for record in records:
        fact = parse_behaviour_record(record)
        assert isinstance(fact, FlowFact | DnsFact)
        start = _floor(fact.ts)
        if bucket is not None and start > bucket:
            events.extend(aggregator.flush(now=bucket + timedelta(minutes=15)))
        bucket = start
        aggregator.record(fact)
    if bucket is not None:
        events.extend(aggregator.flush(now=bucket + timedelta(minutes=15)))
    return events


def replay_fixture(tmp_path: Path, name: str) -> list[Event]:
    """Run one fixture through the real aggregator; attacks first see a normal day."""
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    try:
        aggregator = BehaviourAggregator(
            BehaviourStore(database),
            _device_map(),
            calibration_days=0,
            grace_seconds=0,
        )
        if name == "attack.eve.jsonl":
            _feed(aggregator, _load("normal.eve.jsonl"))
        events = _feed(aggregator, _load(name))
        events.extend(aggregator.close())
        return events
    finally:
        database.close()


def _first_upload_ts() -> datetime:
    for record in _load("attack.eve.jsonl"):
        fact = parse_behaviour_record(record)
        if isinstance(fact, FlowFact) and fact.bytes_toserver > 1_000_000_000:
            return fact.ts
    raise AssertionError("attack fixture has no upload flow")


def test_benign_fixture_produces_no_medium_or_higher_behaviour_alerts(
    tmp_path: Path,
) -> None:
    events = replay_fixture(tmp_path, "normal.eve.jsonl")

    assert [event for event in events if event.severity.rank >= Severity.MEDIUM.rank] == []


def test_benign_fixture_produces_at_most_two_low_beaconing_alerts_per_day(
    tmp_path: Path,
) -> None:
    events = replay_fixture(tmp_path, "normal.eve.jsonl")

    assert len([event for event in events if event.detector == "behaviour.beaconing"]) <= 2


def test_attack_fixture_produces_volume_and_beaconing_events(tmp_path: Path) -> None:
    events = replay_fixture(tmp_path, "attack.eve.jsonl")
    detectors = {event.detector for event in events}

    assert "behaviour.volume_spike" in detectors
    assert "behaviour.beaconing" in detectors
    volume = next(event for event in events if event.detector == "behaviour.volume_spike")
    assert volume.details["ratio"] >= 100


@pytest.mark.parametrize("name", ["normal.eve.jsonl", "attack.eve.jsonl"])
def test_every_fixture_line_parses(name: str) -> None:
    facts = [parse_behaviour_record(record) for record in _load(name)]

    assert all(isinstance(fact, FlowFact | DnsFact) for fact in facts)


def test_attack_beaconing_is_low_and_volume_is_medium(tmp_path: Path) -> None:
    events = replay_fixture(tmp_path, "attack.eve.jsonl")
    volume = next(event for event in events if event.detector == "behaviour.volume_spike")
    beacon = next(event for event in events if event.detector == "behaviour.beaconing")

    assert volume.severity is Severity.MEDIUM
    assert beacon.severity is Severity.LOW


def test_attack_episode_emits_one_beaconing_event(tmp_path: Path) -> None:
    events = replay_fixture(tmp_path, "attack.eve.jsonl")

    assert len([event for event in events if event.detector == "behaviour.beaconing"]) == 1


def test_detection_latency_is_at_most_one_bucket_plus_grace(tmp_path: Path) -> None:
    events = replay_fixture(tmp_path, "attack.eve.jsonl")
    volume = next(event for event in events if event.detector == "behaviour.volume_spike")
    window_end = datetime.fromisoformat(str(volume.details["window_end"]))

    assert window_end - _first_upload_ts() <= timedelta(minutes=15, seconds=30)
