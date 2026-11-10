"""Calibrated scoring, event shape, and the hourly episode cadence."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from gilgamesh.behaviour.aggregate import BehaviourAggregator, BehaviourParams
from gilgamesh.behaviour.attribution import DeviceMap
from gilgamesh.behaviour.eve import FlowFact
from gilgamesh.behaviour.store import BehaviourStore
from gilgamesh.db import Database
from gilgamesh.devices import DeviceRecord
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.rules import RuleConfigService, default_catalogue

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"
IP_A = "10.0.0.20"
IP_B = "10.0.0.21"
NORMAL_DST = "93.184.216.34"


def at(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 11, 1, hour, minute, tzinfo=UTC)


def flow(
    src: str,
    dst: str,
    *,
    out: int,
    in_: int = 0,
    dst_port: int = 443,
    ts: datetime,
) -> FlowFact:
    return FlowFact(
        ts=ts,
        src_ip=src,
        dst_ip=dst,
        src_port=51515,
        dst_port=dst_port,
        proto="TCP",
        app_proto="tls",
        bytes_toserver=out,
        bytes_toclient=in_,
        pkts_toserver=1,
        pkts_toclient=1,
        start=ts,
        end=ts,
        state="established",
    )


class Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.database = Database(tmp_path / "gilgamesh.db")
        self.database.initialize()
        self.store = BehaviourStore(self.database)
        self.devices = DeviceMap()
        self.devices.refresh(
            [
                DeviceRecord(
                    mac=MAC_A,
                    ips=(IP_A,),
                    hostname="Living-room camera",
                    first_ts=at(0),
                    last_ts=at(0),
                ),
                DeviceRecord(
                    mac=MAC_B,
                    ips=(IP_B,),
                    hostname="Phone",
                    first_ts=at(0),
                    last_ts=at(0),
                ),
            ]
        )
        self.aggregator = BehaviourAggregator(
            self.store,
            self.devices,
            calibration_days=0,
            grace_seconds=0,
            clock=lambda: at(12),
        )

    def close(self) -> None:
        self.database.close()

    def normal_bucket(self, bucket_ts: datetime, *, src: str = IP_A) -> None:
        self.aggregator.record(flow(src, NORMAL_DST, out=4_000_000, in_=1_000_000, ts=bucket_ts))

    def flush(self, bucket_ts: datetime) -> list[Event]:
        return self.aggregator.flush(now=bucket_ts + timedelta(seconds=900))

    def calibrate(self, *, src: str = IP_A) -> None:
        start = at(0)
        for index in range(20):
            bucket_ts = start + timedelta(minutes=15 * index)
            self.normal_bucket(bucket_ts, src=src)
            assert self.flush(bucket_ts) == []


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[Harness]:
    subject = Harness(tmp_path)
    yield subject
    subject.close()


def test_volume_spike_emits_one_medium_event_after_calibration(harness: Harness) -> None:
    harness.calibrate()
    attack = at(5)
    harness.aggregator.record(flow(IP_A, NORMAL_DST, out=1_800_000_000, ts=attack))

    events = harness.flush(attack)

    assert len(events) == 1
    event = events[0]
    assert event.type is EventType.BEHAVIOUR_ANOMALY
    assert event.detector == "behaviour.volume_spike"
    assert event.severity is Severity.MEDIUM
    assert event.src_mac == MAC_A
    assert event.src_ip == IP_A
    assert event.dst_ip is None
    assert event.details["signal"] == "volume_spike"
    assert event.details["reason"] == "volume_spike"
    assert event.details["device_label"] == "Living-room camera"
    assert event.details["consecutive_buckets"] == 1
    assert event.details["window_start"] == attack.isoformat()
    assert event.details["window_end"] == (attack + timedelta(minutes=15)).isoformat()
    assert event.details["ratio"] >= 100
    assert "uploaded" in event.summary
    assert "Living-room camera" in event.summary


def test_no_event_before_the_twenty_sample_gate(harness: Harness) -> None:
    start = at(0)
    for index in range(19):
        bucket_ts = start + timedelta(minutes=15 * index)
        harness.normal_bucket(bucket_ts)
        assert harness.flush(bucket_ts) == []

    attack = start + timedelta(minutes=15 * 19)
    harness.aggregator.record(flow(IP_A, NORMAL_DST, out=1_800_000_000, ts=attack))

    assert harness.flush(attack) == []


def test_new_destination_burst_is_one_event_per_hour_with_a_consecutive_count(
    harness: Harness,
) -> None:
    harness.calibrate()
    events: list[Event] = []
    for index in range(5):
        bucket_ts = at(5) + timedelta(minutes=15 * index)
        for host in range(10):
            harness.aggregator.record(
                flow(IP_A, f"203.0.113.{index * 10 + host + 1}", out=1_000, ts=bucket_ts)
            )
        events.extend(harness.flush(bucket_ts))

    assert len(events) == 1
    assert events[0].detector == "behaviour.new_destinations"
    assert events[0].details["new_destinations"] == 10
    assert events[0].details["consecutive_buckets"] == 1


def test_a_second_episode_after_an_hour_emits_again(harness: Harness) -> None:
    harness.calibrate()
    first = at(5)
    for host in range(10):
        harness.aggregator.record(flow(IP_A, f"203.0.113.{host + 1}", out=1_000, ts=first))
    first_events = harness.flush(first)
    assert len(first_events) == 1

    second = at(7, 15)
    for host in range(20):
        harness.aggregator.record(flow(IP_A, f"198.51.100.{host + 1}", out=1_000, ts=second))
    second_events = harness.flush(second)

    assert len(second_events) == 1
    assert second_events[0].details["new_destinations"] == 20
    assert second_events[0].details["consecutive_buckets"] == 1


def test_two_devices_with_the_same_signal_do_not_collide(harness: Harness) -> None:
    harness.calibrate()
    harness.calibrate(src=IP_B)
    bucket_ts = at(5)
    for host in range(10):
        harness.aggregator.record(flow(IP_A, f"203.0.113.{host + 1}", out=1_000, ts=bucket_ts))
        harness.aggregator.record(flow(IP_B, f"198.51.100.{host + 1}", out=1_000, ts=bucket_ts))

    events = harness.flush(bucket_ts)

    assert len(events) == 2
    assert {event.src_ip for event in events} == {IP_A, IP_B}
    assert len({event.dedup_key for event in events}) == 2


def test_beaconing_event_is_low_and_sets_dst_ip(harness: Harness) -> None:
    harness.calibrate()
    bucket_ts = at(5)
    for index in range(8):
        harness.aggregator.record(
            flow(
                IP_A,
                "203.0.113.9",
                out=5_000,
                ts=bucket_ts + timedelta(seconds=60 * index),
            )
        )

    events = harness.flush(bucket_ts)

    assert len(events) == 1
    event = events[0]
    assert event.detector == "behaviour.beaconing"
    assert event.severity is Severity.LOW
    assert event.dst_ip == "203.0.113.9"
    assert event.details["connections"] == 8
    assert event.details["dst_port"] == 443
    assert "regular connections" in event.summary


def test_behaviour_params_read_the_owner_values(harness: Harness) -> None:
    rules = RuleConfigService(harness.database, default_catalogue())
    rules.set_params("behaviour.volume_spike", {"min_bytes": 50_000_000, "min_ratio": 25})

    params = BehaviourParams.from_rules(rules)

    assert params.min_bytes == 50_000_000
    assert params.min_ratio == 25.0
    assert params.min_new == 8
    assert params.min_connections == 8
