"""Parsing Suricata 8 EVE ``flow`` and ``dns`` records into behaviour facts.

The field names come from Suricata 8's EVE JSON format: flows carry
``flow.bytes_toserver``/``flow.bytes_toclient`` and ``flow.start``/``flow.end``;
DNS queries live under ``dns.queries[]`` (version 3) with the older ``dns.rrname``
scalar accepted as a fallback. Parsing never raises: the behaviour tailer runs
unattended, so a malformed record must be skipped, not crash the sensor.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from gilgamesh.behaviour.eve import (
    DnsFact,
    FlowFact,
    parse_behaviour_record,
    parse_dns_record,
    parse_flow_record,
    parse_suricata_ts,
)

NOW = datetime(2026, 11, 1, 2, 0, tzinfo=UTC)


def flow_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "timestamp": "2026-11-01T02:14:59.000000+0000",
        "event_type": "flow",
        "src_ip": "10.0.0.20",
        "dest_ip": "93.184.216.34",
        "src_port": 51515,
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "flow": {
            "bytes_toserver": 4000,
            "bytes_toclient": 1200,
            "pkts_toserver": 10,
            "pkts_toclient": 8,
            "start": "2026-11-01T02:01:00.000000+0000",
            "end": "2026-11-01T02:15:00.000000+0000",
            "state": "established",
        },
    }
    record.update(overrides)
    return record


def dns_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "timestamp": "2026-11-01T02:00:00.000000+0000",
        "event_type": "dns",
        "src_ip": "10.0.0.20",
        "dest_ip": "10.0.0.1",
        "proto": "UDP",
        "dns": {
            "type": "request",
            "rcode": "NOERROR",
            "queries": [{"rrname": "example.com", "rrtype": "A"}],
        },
    }
    record.update(overrides)
    return record


def test_flow_uses_flow_end_for_the_bucket_timestamp() -> None:
    fact = parse_flow_record(flow_record())

    assert fact is not None
    assert fact.ts == datetime(2026, 11, 1, 2, 15, tzinfo=UTC)
    assert (fact.bytes_toserver, fact.bytes_toclient) == (4000, 1200)
    assert (fact.pkts_toserver, fact.pkts_toclient) == (10, 8)
    assert fact.src_ip == "10.0.0.20"
    assert fact.dst_ip == "93.184.216.34"
    assert (fact.src_port, fact.dst_port) == (51515, 443)
    assert (fact.proto, fact.app_proto) == ("TCP", "tls")
    assert fact.state == "established"
    assert fact.start == datetime(2026, 11, 1, 2, 1, tzinfo=UTC)


def test_dns_v3_queries_are_read_from_queries_list() -> None:
    fact = parse_dns_record(dns_record())

    assert isinstance(fact, DnsFact)
    assert fact.names == ("example.com",)
    assert fact.is_response is False
    assert fact.rcode == "NOERROR"
    assert fact.ts == NOW


def test_non_flow_or_dns_record_is_ignored() -> None:
    assert parse_behaviour_record({"event_type": "alert"}) is None
    assert parse_behaviour_record({"event_type": "http"}) is None
    assert parse_behaviour_record({}) is None


def test_parse_behaviour_record_dispatches_by_event_type() -> None:
    assert isinstance(parse_behaviour_record(flow_record()), FlowFact)
    assert isinstance(parse_behaviour_record(dns_record()), DnsFact)


def test_flow_with_an_invalid_ip_is_ignored() -> None:
    assert parse_flow_record(flow_record(src_ip="not-an-ip")) is None
    assert parse_flow_record(flow_record(dest_ip="10.0.0.999")) is None


def test_flow_without_a_flow_object_is_ignored() -> None:
    record = flow_record()
    del record["flow"]
    assert parse_flow_record(record) is None
    assert parse_flow_record(flow_record(flow="not-a-mapping")) is None


def test_negative_counts_are_clamped_to_zero() -> None:
    fact = parse_flow_record(
        flow_record(
            flow={
                "bytes_toserver": -5,
                "bytes_toclient": -1,
                "pkts_toserver": -3,
                "pkts_toclient": -2,
                "end": "2026-11-01T02:15:00.000000+0000",
            }
        )
    )

    assert fact is not None
    assert (fact.bytes_toserver, fact.bytes_toclient) == (0, 0)
    assert (fact.pkts_toserver, fact.pkts_toclient) == (0, 0)


def test_invalid_flow_end_falls_back_to_the_record_timestamp() -> None:
    fact = parse_flow_record(flow_record(flow={"bytes_toserver": 1, "end": "not-a-time"}))

    assert fact is not None
    assert fact.ts == datetime(2026, 11, 1, 2, 14, 59, tzinfo=UTC)


def test_a_flow_with_no_usable_timestamp_is_ignored() -> None:
    assert (
        parse_flow_record(
            flow_record(timestamp="bad", flow={"bytes_toserver": 1, "end": "also bad"})
        )
        is None
    )


def test_older_dns_rrname_scalar_is_a_fallback() -> None:
    record = dns_record(dns={"type": "request", "rcode": "NOERROR", "rrname": "legacy.test"})

    fact = parse_dns_record(record)

    assert fact is not None
    assert fact.names == ("legacy.test",)


def test_dns_with_no_names_is_ignored() -> None:
    assert parse_dns_record(dns_record(dns={"type": "request", "rcode": "NOERROR"})) is None
    assert parse_dns_record(dns_record(dns={"queries": []})) is None


def test_dns_response_flag_is_read_from_dns_type() -> None:
    fact = parse_dns_record(
        dns_record(
            dns={
                "type": "response",
                "rcode": "NXDOMAIN",
                "queries": [{"rrname": "missing.example"}],
            }
        )
    )

    assert fact is not None
    assert fact.is_response is True
    assert fact.rcode == "NXDOMAIN"


def test_dns_names_are_normalized() -> None:
    fact = parse_dns_record(
        dns_record(
            dns={
                "type": "request",
                "queries": [{"rrname": "Example.COM."}, {"rrname": "example.com"}],
            }
        )
    )

    assert fact is not None
    assert fact.names == ("example.com", "example.com")


def test_ipv6_facts_are_returned_normalized() -> None:
    fact = parse_flow_record(flow_record(src_ip="2001:0db8::1", dest_ip="2001:db8::2"))

    assert fact is not None
    assert fact.src_ip == "2001:db8::1"
    assert fact.dst_ip == "2001:db8::2"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-11-01T02:00:00.000000+0000", NOW),
        ("2026-11-01T02:00:00+00:00", NOW),
        ("2026-11-01T02:00:00Z", NOW),
        ("2026-11-01T02:00:00", NOW),
        (None, None),
        ("", None),
        ("not-a-time", None),
        (12345, None),
    ],
)
def test_parse_suricata_ts(value: object, expected: datetime | None) -> None:
    assert parse_suricata_ts(value) == expected


def test_malformed_records_never_raise() -> None:
    bad: list[dict[str, object]] = [
        {"event_type": "flow", "src_ip": 42, "dest_ip": None, "flow": None},
        {"event_type": "dns", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "dns": []},
        {"event_type": "dns", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "dns": {"queries": "x"}},
    ]

    for record in bad:
        assert parse_behaviour_record(record) is None
