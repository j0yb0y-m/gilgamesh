"""Aggregate flow and DNS facts into per-device 15-minute buckets."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gilgamesh.behaviour.aggregate import BehaviourAggregator
from gilgamesh.behaviour.attribution import DeviceMap
from gilgamesh.behaviour.eve import DnsFact, FlowFact
from gilgamesh.behaviour.store import BehaviourStore
from gilgamesh.db import Database
from gilgamesh.devices import DeviceRecord

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"
IP_A = "10.0.0.20"
IP_B = "10.0.0.21"


def at(hour: int, minute: int, second: int = 0) -> datetime:
    return datetime(2026, 11, 1, hour, minute, second, tzinfo=UTC)


def flow(
    src: str,
    dst: str,
    *,
    out: int = 0,
    in_: int = 0,
    pkts_out: int = 0,
    pkts_in: int = 0,
    ts: datetime | None = None,
) -> FlowFact:
    return FlowFact(
        ts=ts or at(10, 7),
        src_ip=src,
        dst_ip=dst,
        src_port=51515,
        dst_port=443,
        proto="TCP",
        app_proto="tls",
        bytes_toserver=out,
        bytes_toclient=in_,
        pkts_toserver=pkts_out,
        pkts_toclient=pkts_in,
        start=None,
        end=ts or at(10, 7),
        state="established",
    )


def dns(src: str, *names: str, response: bool = False, ts: datetime | None = None) -> DnsFact:
    return DnsFact(
        ts=ts or at(10, 7),
        src_ip=src,
        dst_ip="10.0.0.1",
        names=names,
        rcode="NOERROR",
        is_response=response,
    )


@pytest.fixture
def store(tmp_path: Path) -> Iterator[BehaviourStore]:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    yield BehaviourStore(database)
    database.close()


@pytest.fixture
def devices() -> DeviceMap:
    device_map = DeviceMap()
    device_map.refresh(
        [
            DeviceRecord(mac=MAC_A, ips=(IP_A,), first_ts=at(9, 0), last_ts=at(9, 0)),
            DeviceRecord(mac=MAC_B, ips=(IP_B,), first_ts=at(9, 0), last_ts=at(9, 0)),
        ]
    )
    return device_map


def test_outbound_flow_updates_the_source_device_bucket(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)

    aggregator.record(flow(IP_A, "93.184.216.34", out=4000, in_=1200, pkts_out=10, pkts_in=8))
    aggregator.flush(now=at(10, 30))

    bucket = store.buckets(MAC_A, since=at(10, 0))[0]
    assert bucket.bucket_ts == at(10, 0)
    assert (bucket.bytes_out, bucket.bytes_in) == (4000, 1200)
    assert (bucket.packets_out, bucket.packets_in) == (10, 8)
    assert bucket.flows == 1
    assert bucket.unique_dst == 1


def test_inbound_flow_updates_the_destination_device_bucket(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)

    aggregator.record(flow("93.184.216.34", IP_A, out=4000, in_=1200, pkts_out=10, pkts_in=8))
    aggregator.flush(now=at(10, 30))

    bucket = store.buckets(MAC_A, since=at(10, 0))[0]
    assert (bucket.bytes_in, bucket.bytes_out) == (4000, 1200)
    assert (bucket.packets_in, bucket.packets_out) == (10, 8)
    assert bucket.flows == 1
    assert bucket.unique_dst == 0


def test_lan_to_lan_flow_counts_for_both_devices_without_external_dst(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)

    aggregator.record(flow(IP_A, IP_B, out=100, in_=50, pkts_out=2, pkts_in=1))
    aggregator.flush(now=at(10, 30))

    source = store.buckets(MAC_A, since=at(10, 0))[0]
    destination = store.buckets(MAC_B, since=at(10, 0))[0]
    assert (source.bytes_out, source.bytes_in, source.flows, source.unique_dst) == (100, 50, 1, 0)
    assert (
        destination.bytes_in,
        destination.bytes_out,
        destination.flows,
        destination.unique_dst,
    ) == (100, 50, 1, 0)


def test_unknown_and_ipv6_flows_are_counted_but_create_no_device_rows(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)

    aggregator.record(flow("203.0.113.9", "10.0.0.99", out=100))
    aggregator.record(flow("2001:db8::1", "2001:db8::2", out=100))
    aggregator.flush(now=at(10, 30))

    assert aggregator.status.unknown_ip_flows == 2
    assert aggregator.status.ipv6_flows == 1
    assert store.buckets(MAC_A, since=at(10, 0)) == []
    assert store.buckets(MAC_B, since=at(10, 0)) == []


def test_ipv6_flow_is_not_attributed_even_when_the_address_is_in_the_inventory(
    store: BehaviourStore,
) -> None:
    devices = DeviceMap()
    devices.refresh(
        [DeviceRecord(mac=MAC_A, ips=("2001:db8::1",), first_ts=at(9, 0), last_ts=at(9, 0))]
    )
    aggregator = BehaviourAggregator(store, devices)

    aggregator.record(flow("2001:db8::1", "2001:db8::2", out=100))
    aggregator.flush(now=at(10, 30))

    assert aggregator.status.unknown_ip_flows == 1
    assert aggregator.status.ipv6_flows == 1
    assert store.buckets(MAC_A, since=at(10, 0)) == []


def test_internal_unknown_destination_does_not_count_as_external(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)

    aggregator.record(flow(IP_A, "10.0.0.99", out=100))
    aggregator.flush(now=at(10, 30))

    bucket = store.buckets(MAC_A, since=at(10, 0))[0]
    assert bucket.bytes_out == 100
    assert bucket.unique_dst == 0


def test_dns_request_counts_queries_and_distinct_names(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)

    aggregator.record(dns(IP_A, "example.com", "example.com", "cdn.example.net"))
    aggregator.flush(now=at(10, 30))

    bucket = store.buckets(MAC_A, since=at(10, 0))[0]
    assert bucket.dns_queries == 1
    assert bucket.dns_unique_names == 2
    assert bucket.flows == 0


def test_dns_response_increments_only_the_status_counter(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)

    aggregator.record(dns(IP_A, "example.com", response=True))
    aggregator.flush(now=at(10, 30))

    assert aggregator.status.dns_seen == 1
    assert store.buckets(MAC_A, since=at(10, 0)) == []


def test_flow_end_at_the_boundary_belongs_to_the_next_bucket(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)

    aggregator.record(flow(IP_A, "93.184.216.34", out=1, ts=at(10, 15)))
    aggregator.flush(now=at(10, 46))

    bucket = store.buckets(MAC_A, since=at(10, 0))[0]
    assert bucket.bucket_ts == at(10, 15)


def test_flush_waits_for_the_grace_window_and_close_flushes(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)
    aggregator.record(flow(IP_A, "93.184.216.34", out=100))

    assert aggregator.flush(now=at(10, 15)) == []
    assert store.buckets(MAC_A, since=at(10, 0)) == []

    assert aggregator.close() == []
    assert store.buckets(MAC_A, since=at(10, 0))[0].bytes_out == 100
    assert aggregator.tracked_devices == 0


def test_a_late_fact_is_written_additively_and_counted(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices)
    aggregator.record(flow(IP_A, "93.184.216.34", out=100))
    aggregator.flush(now=at(10, 30))

    aggregator.record(flow(IP_A, "93.184.216.34", out=50, ts=at(10, 8)))
    aggregator.flush(now=at(11, 0))

    bucket = store.buckets(MAC_A, since=at(10, 0))[0]
    assert bucket.bytes_out == 150
    assert aggregator.status.late_buckets == 1


def test_a_new_bucket_after_a_flush_is_not_late(store: BehaviourStore, devices: DeviceMap) -> None:
    aggregator = BehaviourAggregator(store, devices)
    aggregator.record(flow(IP_A, "93.184.216.34", out=100))
    aggregator.flush(now=at(10, 30))

    aggregator.record(flow(IP_A, "93.184.216.34", out=50, ts=at(10, 20)))
    aggregator.flush(now=at(11, 0))

    buckets = store.buckets(MAC_A, since=at(10, 0))
    assert [bucket.bytes_out for bucket in buckets] == [100, 50]
    assert aggregator.status.late_buckets == 0


def test_max_devices_bounds_the_window_and_counts_drops(
    store: BehaviourStore, devices: DeviceMap
) -> None:
    aggregator = BehaviourAggregator(store, devices, max_devices=1)

    aggregator.record(flow(IP_A, "93.184.216.34", out=100))
    aggregator.record(flow(IP_B, "93.184.216.34", out=100))

    assert aggregator.tracked_devices == 1
    assert aggregator.status.devices_dropped == 1


def test_max_bucket_destinations_caps_unique_dst(store: BehaviourStore, devices: DeviceMap) -> None:
    aggregator = BehaviourAggregator(store, devices, max_bucket_destinations=2)

    for index in range(4):
        aggregator.record(flow(IP_A, f"93.184.216.{index + 1}", out=1))
    aggregator.flush(now=at(10, 30))

    assert store.buckets(MAC_A, since=at(10, 0))[0].unique_dst == 2


def test_status_reports_counters_and_timestamps(store: BehaviourStore, devices: DeviceMap) -> None:
    aggregator = BehaviourAggregator(store, devices, clock=lambda: at(10, 30))

    aggregator.record(flow(IP_A, "93.184.216.34", out=1, ts=at(10, 7)))
    aggregator.record(dns(IP_A, "example.com", ts=at(10, 8)))
    status = aggregator.status

    assert status.flows_seen == 1
    assert status.dns_seen == 1
    assert status.last_flow_ts == at(10, 7)
    assert status.last_dns_ts == at(10, 8)
    assert status.devices_tracked == 1
    assert status.updated_ts == at(10, 30)
