"""The sensor-side behaviour service: batching, status, disable, and shutdown."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from threading import Event as ThreadEvent
from threading import Thread

import pytest

from gilgamesh.behaviour.service import (
    POSITION_KEY_PREFIX,
    AggregatorFactory,
    BehaviourService,
    FollowerFactory,
    start_behaviour_service,
)
from gilgamesh.behaviour.store import BehaviourStatus, BehaviourStore
from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.preferences import PreferencesStore

MAC_A = "aa:bb:cc:dd:ee:01"
IP_A = "10.0.0.20"
NOW = datetime(2026, 11, 1, 10, 30, tzinfo=UTC)
BUCKET = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)


def flow_record(
    *, src: str = IP_A, dst: str = "93.184.216.34", ts: str = "2026-11-01T10:07:00.000000+0000"
) -> dict[str, object]:
    return {
        "timestamp": ts,
        "event_type": "flow",
        "src_ip": src,
        "dest_ip": dst,
        "src_port": 51515,
        "dest_port": 443,
        "proto": "TCP",
        "flow": {
            "bytes_toserver": 4000,
            "bytes_toclient": 1200,
            "pkts_toserver": 10,
            "pkts_toclient": 8,
            "end": ts,
        },
    }


class FakeFollower:
    """A follower that yields records, then waits for the producer stop event."""

    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = records
        self.calls: list[str] = []
        self.yielded = ThreadEvent()
        self.second_call = ThreadEvent()

    def __call__(
        self, path: Path, database: Database, position_key: str, stop: ThreadEvent
    ) -> Iterator[dict[str, object]]:
        self.calls.append(position_key)
        if len(self.calls) >= 2:
            self.second_call.set()
        yield from self.records
        self.yielded.set()
        stop.wait(2.0)


class StubAggregator:
    def __init__(self, events: list[Event]) -> None:
        self.events = events
        self.recorded: list[object] = []
        self.status = BehaviourStatus(flows_seen=1)

    def record(self, fact: object) -> None:
        self.recorded.append(fact)

    def flush(self, now: datetime | None = None) -> list[Event]:
        return self.events

    def close(self) -> list[Event]:
        return self.events


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def device_store(database: Database) -> DeviceStore:
    store = DeviceStore(database)
    store.upsert(MAC_A, ip=IP_A, seen_ts=BUCKET)
    return store


@pytest.fixture
def preferences(database: Database) -> PreferencesStore:
    return PreferencesStore(database)


def service(
    database: Database,
    device_store: DeviceStore,
    preferences: PreferencesStore,
    *,
    eve_path: Path | None = None,
    submit_event: Callable[[Event], bool] | None = None,
    follower_factory: FollowerFactory | None = None,
    aggregator_factory: AggregatorFactory | None = None,
    clock: Callable[[], datetime] | None = None,
) -> BehaviourService:
    return BehaviourService(
        database,
        device_store,
        preferences,
        eve_path=eve_path,
        submit_event=submit_event or (lambda _event: True),
        follower_factory=follower_factory,
        aggregator_factory=aggregator_factory,
        clock=clock,
    )


def test_run_once_writes_a_bucket_and_submits_no_events_before_calibration(
    database: Database, device_store: DeviceStore, preferences: PreferencesStore
) -> None:
    submitted: list[Event] = []
    subject = service(
        database,
        device_store,
        preferences,
        submit_event=lambda event: submitted.append(event) or True,
        clock=lambda: NOW,
    )

    events = subject.run_once([flow_record()], now=NOW)

    assert events == []
    assert submitted == []
    bucket = BehaviourStore(database).buckets(MAC_A, since=BUCKET)[0]
    assert bucket.bytes_out == 4000
    assert BehaviourStore(database).read_status().flows_seen == 1


def test_disabled_behaviour_writes_nothing_and_reports_disabled(
    database: Database, device_store: DeviceStore, preferences: PreferencesStore
) -> None:
    preferences.update(behaviour_enabled=False)
    subject = service(database, device_store, preferences, clock=lambda: NOW)

    assert subject.run_once([flow_record()], now=NOW) == []

    assert BehaviourStore(database).buckets(MAC_A, since=BUCKET) == []
    status = BehaviourStore(database).read_status()
    assert status.enabled is False
    assert status.flows_seen == 0


def test_parse_errors_count_only_broken_flow_and_dns_records(
    database: Database, device_store: DeviceStore, preferences: PreferencesStore
) -> None:
    subject = service(database, device_store, preferences, clock=lambda: NOW)

    subject.run_once(
        [
            {"event_type": "alert"},
            {"event_type": "http"},
            {"event_type": "flow", "src_ip": "bad"},
            flow_record(),
        ],
        now=NOW,
    )

    status = BehaviourStore(database).read_status()
    assert status.parse_errors == 1
    assert status.flows_seen == 1


def test_run_once_submits_events_returned_by_the_aggregator(
    database: Database, device_store: DeviceStore, preferences: PreferencesStore
) -> None:
    event = Event(
        id="evt-1",
        ts=NOW,
        type=EventType.TEST,
        severity=Severity.MEDIUM,
        detector="behaviour.volume_spike",
        summary="test",
        src_ip=IP_A,
        details={},
    )
    stub = StubAggregator([event])
    submitted: list[Event] = []
    subject = service(
        database,
        device_store,
        preferences,
        submit_event=lambda event: submitted.append(event) or True,
        aggregator_factory=lambda _store, _devices: stub,
        clock=lambda: NOW,
    )

    events = subject.run_once([flow_record()], now=NOW)

    assert events == [event]
    assert submitted == [event]
    assert len(stub.recorded) == 1


def test_run_follows_eve_and_stops_within_two_seconds(
    tmp_path: Path, database: Database, device_store: DeviceStore, preferences: PreferencesStore
) -> None:
    path = tmp_path / "eve.json"
    path.write_text("")
    follower = FakeFollower([flow_record()])
    subject = service(
        database,
        device_store,
        preferences,
        eve_path=path,
        follower_factory=follower,
        clock=lambda: NOW,
    )
    stop = ThreadEvent()
    thread = Thread(target=subject.run, args=(stop,))
    thread.start()

    assert follower.yielded.wait(2.0)
    stop.set()
    thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert follower.calls == [f"{POSITION_KEY_PREFIX}{path}"]
    bucket = BehaviourStore(database).buckets(MAC_A, since=BUCKET)[0]
    assert bucket.bytes_out == 4000
    status = BehaviourStore(database).read_status()
    assert status.flows_seen == 1
    assert status.suricata_available is True


def test_run_without_an_eve_path_publishes_unavailable_and_returns(
    database: Database, device_store: DeviceStore, preferences: PreferencesStore
) -> None:
    subject = service(database, device_store, preferences, eve_path=None)
    stop = ThreadEvent()
    stop.set()

    subject.run(stop)

    status = BehaviourStore(database).read_status()
    assert status.suricata_available is False
    assert status.enabled is True


def test_disabling_then_reenabling_resumes_with_the_same_position(
    tmp_path: Path,
    database: Database,
    device_store: DeviceStore,
    preferences: PreferencesStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BehaviourService, "DISABLE_RETRY_SECONDS", 0.01)
    path = tmp_path / "eve.json"
    path.write_text("")
    follower = FakeFollower([flow_record()])
    subject = service(
        database,
        device_store,
        preferences,
        eve_path=path,
        follower_factory=follower,
        clock=lambda: NOW,
    )
    stop = ThreadEvent()
    thread = Thread(target=subject.run, args=(stop,))
    thread.start()
    assert follower.yielded.wait(2.0)

    preferences.update(behaviour_enabled=False)
    deadline = time.monotonic() + 2.0
    while BehaviourStore(database).read_status().enabled and time.monotonic() < deadline:
        time.sleep(0.01)
    assert BehaviourStore(database).read_status().enabled is False

    preferences.update(behaviour_enabled=True)
    assert follower.second_call.wait(2.0)

    stop.set()
    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert follower.calls == [f"{POSITION_KEY_PREFIX}{path}"] * 2


def test_start_behaviour_service_returns_none_without_an_eve_path(
    database: Database, device_store: DeviceStore, preferences: PreferencesStore
) -> None:
    class Sink:
        def submit_event(self, event: Event) -> bool:
            return True

    stop = ThreadEvent()
    assert start_behaviour_service(None, Sink(), stop, database, device_store, preferences) is None


def test_start_behaviour_service_starts_and_stops_a_thread(
    tmp_path: Path, database: Database, device_store: DeviceStore, preferences: PreferencesStore
) -> None:
    class Sink:
        def submit_event(self, event: Event) -> bool:
            return True

    path = tmp_path / "eve.json"
    path.write_text("")
    stop = ThreadEvent()
    stop.set()

    thread = start_behaviour_service(path, Sink(), stop, database, device_store, preferences)

    assert thread is not None
    thread.join(timeout=2.0)
    assert not thread.is_alive()
