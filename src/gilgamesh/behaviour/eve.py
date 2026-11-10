"""Turn Suricata EVE ``flow`` and ``dns`` records into behaviour facts.

This module is deliberately narrow: it reads only the fields the behaviour engine
needs, normalizes addresses and timestamps, and never raises for a malformed
record. A tailer runs unattended, so one bad line must be skipped, not crash the
sensor.

Suricata 8 writes DNS version 3: queries are a list under ``dns.queries[]`` and
answers under ``dns.answers[]``. The older scalar ``dns.rrname`` is accepted as a
fallback so a mixed-version deployment still yields names.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast


@dataclass(frozen=True, slots=True)
class FlowFact:
    """One ``flow`` record, reduced to what attribution and scoring need."""

    ts: datetime
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    proto: str | None
    app_proto: str | None
    bytes_toserver: int
    bytes_toclient: int
    pkts_toserver: int
    pkts_toclient: int
    start: datetime | None
    end: datetime | None
    state: str | None


@dataclass(frozen=True, slots=True)
class DnsFact:
    """One ``dns`` record, reduced to the query names and response flag."""

    ts: datetime
    src_ip: str
    dst_ip: str
    names: tuple[str, ...]
    rcode: str | None
    is_response: bool


def parse_suricata_ts(value: object) -> datetime | None:
    """Parse Suricata's ISO-8601 timestamp, or return ``None``.

    EVE writes ``2026-11-01T02:15:00.000000+0000``. Python 3.13 accepts that shape,
    but the trailing ``+0000`` is rewritten to ``+00:00`` for older spellings and
    for clarity. A naive value is treated as UTC, which is what Suricata writes.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("+0000"):
        text = f"{text[:-5]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_flow_record(record: Mapping[str, object]) -> FlowFact | None:
    """Parse one EVE ``flow`` record, or return ``None``."""
    if record.get("event_type") != "flow":
        return None

    src_ip = _normalize_ip(record.get("src_ip"))
    dst_ip = _normalize_ip(record.get("dest_ip"))
    if src_ip is None or dst_ip is None:
        return None

    flow = _mapping(record.get("flow"))
    if flow is None:
        return None

    end = parse_suricata_ts(flow.get("end"))
    ts = end if end is not None else parse_suricata_ts(record.get("timestamp"))
    if ts is None:
        return None

    return FlowFact(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=_port(record.get("src_port")),
        dst_port=_port(record.get("dest_port")),
        proto=_text(record.get("proto")),
        app_proto=_text(record.get("app_proto")),
        bytes_toserver=_count(flow.get("bytes_toserver")),
        bytes_toclient=_count(flow.get("bytes_toclient")),
        pkts_toserver=_count(flow.get("pkts_toserver")),
        pkts_toclient=_count(flow.get("pkts_toclient")),
        start=parse_suricata_ts(flow.get("start")),
        end=end,
        state=_text(flow.get("state")),
    )


def parse_dns_record(record: Mapping[str, object]) -> DnsFact | None:
    """Parse one EVE ``dns`` record, or return ``None`` when it carries no name."""
    if record.get("event_type") != "dns":
        return None

    src_ip = _normalize_ip(record.get("src_ip"))
    dst_ip = _normalize_ip(record.get("dest_ip"))
    if src_ip is None or dst_ip is None:
        return None

    dns = _mapping(record.get("dns"))
    if dns is None:
        return None

    ts = parse_suricata_ts(record.get("timestamp"))
    if ts is None:
        return None

    names = _dns_names(dns)
    if not names:
        return None

    rcode = dns.get("rcode")
    return DnsFact(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        names=names,
        rcode=rcode if isinstance(rcode, str) else None,
        is_response=dns.get("type") == "response",
    )


def parse_behaviour_record(record: Mapping[str, object]) -> FlowFact | DnsFact | None:
    """Dispatch one decoded EVE record to the matching fact parser."""
    kind = record.get("event_type")
    if kind == "flow":
        return parse_flow_record(record)
    if kind == "dns":
        return parse_dns_record(record)
    return None


def _dns_names(dns: Mapping[str, object]) -> tuple[str, ...]:
    names: list[str] = []
    queries = dns.get("queries")
    if isinstance(queries, list):
        for item in cast("list[object]", queries):
            query = _mapping(item)
            if query is not None:
                name = _normalize_name(query.get("rrname"))
                if name is not None:
                    names.append(name)
    if not names:
        name = _normalize_name(dns.get("rrname"))
        if name is not None:
            names.append(name)
    return tuple(names)


def _mapping(value: object) -> Mapping[str, object] | None:
    """Narrow a decoded JSON value to a string-keyed mapping."""
    if isinstance(value, Mapping):
        return cast("Mapping[str, object]", value)
    return None


def _normalize_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip().rstrip(".").lower()
    return name or None


def _normalize_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0
    return max(0, int(value))


def _port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    port = int(value)
    return port if 0 <= port <= 65535 else None
