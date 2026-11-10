"""Persistence for the behaviour engine's aggregates, baselines, and status.

The engine writes one row per device per 15-minute bucket. Upserts are absolute by
default (the aggregator owns the bucket and rewrites it) and additive only when a
caller explicitly asks, which keeps a late flush from double-counting.

Destination memory is bounded per device. It survives sensor restarts, so a reboot
does not make every destination look new.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from gilgamesh.db import Database
from gilgamesh.models import Event
from gilgamesh.util.net import normalize_mac

_STATUS_KEY = "behaviour_status"
_BYTES_OUT_METRIC = "bytes_out_log"

_BUCKET_FIELDS = (
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    "flows",
    "unique_dst",
    "dns_queries",
    "dns_unique_names",
)


@dataclass(frozen=True, slots=True)
class ActivityBucket:
    """One device's traffic in one 15-minute bucket."""

    device_mac: str
    bucket_ts: datetime
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    flows: int = 0
    unique_dst: int = 0
    dns_queries: int = 0
    dns_unique_names: int = 0

    def __post_init__(self) -> None:
        if self.bucket_ts.tzinfo is None:
            raise ValueError("bucket_ts must be timezone-aware")
        for field in _BUCKET_FIELDS:
            if getattr(self, field) < 0:
                raise ValueError(f"{field} must be non-negative")


@dataclass(frozen=True, slots=True)
class BaselineRow:
    """One device/metric EWMA baseline row."""

    device_mac: str
    metric: str
    mean: float
    variance: float
    samples: int
    learning_started_ts: datetime
    updated_ts: datetime


BehaviourState = Literal["disabled", "none", "learning", "calibrated"]


@dataclass(frozen=True, slots=True)
class DeviceBehaviourSummary:
    """What the Devices list needs to know about one device's calibration."""

    mac: str
    state: BehaviourState
    days_learning: int
    calibration_days: int
    samples: int
    updated_ts: datetime | None = None


@dataclass(frozen=True, slots=True)
class DeviceProfile:
    """Everything the device-detail page renders for one device."""

    summary: DeviceBehaviourSummary
    buckets: tuple[ActivityBucket, ...]
    baselines: tuple[BaselineRow, ...]
    recent_events: tuple[Event, ...]


class BehaviourStatus(BaseModel):
    """What the Health page shows about the behaviour engine.

    Defaults describe a fresh install: behaviour is enabled but Suricata has not
    been heard from yet, and nothing has been counted.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    updated_ts: datetime | None = None
    last_flow_ts: datetime | None = None
    last_dns_ts: datetime | None = None
    flows_seen: int = 0
    dns_seen: int = 0
    parse_errors: int = 0
    unknown_ip_flows: int = 0
    ipv6_flows: int = 0
    devices_tracked: int = 0
    devices_dropped: int = 0
    late_buckets: int = 0
    last_flush_ts: datetime | None = None
    enabled: bool = True
    suricata_available: bool = False


class BehaviourStore:
    """Read and write the behaviour tables through :class:`Database`."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def write_bucket(self, bucket: ActivityBucket, *, additive: bool = False) -> None:
        """Insert or update one bucket.

        ``additive=True`` adds to the stored values; the default replaces them, so
        replaying the same in-memory bucket cannot inflate it.
        """
        if additive:
            updates = (
                "bytes_in = device_activity.bytes_in + excluded.bytes_in, "
                "bytes_out = device_activity.bytes_out + excluded.bytes_out, "
                "packets_in = device_activity.packets_in + excluded.packets_in, "
                "packets_out = device_activity.packets_out + excluded.packets_out, "
                "flows = device_activity.flows + excluded.flows, "
                "unique_dst = device_activity.unique_dst + excluded.unique_dst, "
                "dns_queries = device_activity.dns_queries + excluded.dns_queries, "
                "dns_unique_names = device_activity.dns_unique_names + excluded.dns_unique_names"
            )
        else:
            updates = (
                "bytes_in = excluded.bytes_in, "
                "bytes_out = excluded.bytes_out, "
                "packets_in = excluded.packets_in, "
                "packets_out = excluded.packets_out, "
                "flows = excluded.flows, "
                "unique_dst = excluded.unique_dst, "
                "dns_queries = excluded.dns_queries, "
                "dns_unique_names = excluded.dns_unique_names"
            )
        self._db.execute(
            # Only the constant column list and assignment list above are interpolated;
            # every value is bound.
            "INSERT INTO device_activity (device_mac, bucket_ts, bytes_in, bytes_out, "  # noqa: S608
            "packets_in, packets_out, flows, unique_dst, dns_queries, dns_unique_names) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            f"ON CONFLICT(device_mac, bucket_ts) DO UPDATE SET {updates}",
            (
                normalize_mac(bucket.device_mac),
                _iso(bucket.bucket_ts),
                *(getattr(bucket, field) for field in _BUCKET_FIELDS),
            ),
        )

    def buckets(self, device_mac: str, *, since: datetime) -> list[ActivityBucket]:
        """Buckets for ``device_mac`` at or after ``since``, oldest first."""
        rows = self._db.query(
            "SELECT * FROM device_activity WHERE device_mac = ? AND bucket_ts >= ? "
            "ORDER BY bucket_ts ASC",
            (normalize_mac(device_mac), _iso(since)),
        )
        return [
            ActivityBucket(
                device_mac=row["device_mac"],
                bucket_ts=_parse_ts(row["bucket_ts"]),
                **{field: int(row[field]) for field in _BUCKET_FIELDS},
            )
            for row in rows
        ]

    def load_baselines(self) -> list[BaselineRow]:
        """Every stored baseline, ordered by device then metric."""
        rows = self._db.query("SELECT * FROM device_baselines ORDER BY device_mac, metric")
        return [_row_to_baseline(row) for row in rows]

    def upsert_baseline(self, row: BaselineRow) -> None:
        """Insert or replace one device/metric baseline."""
        self._db.execute(
            "INSERT INTO device_baselines "
            "(device_mac, metric, mean, variance, samples, learning_started_ts, updated_ts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(device_mac, metric) DO UPDATE SET "
            "mean = excluded.mean, variance = excluded.variance, samples = excluded.samples, "
            "learning_started_ts = excluded.learning_started_ts, updated_ts = excluded.updated_ts",
            (
                normalize_mac(row.device_mac),
                row.metric,
                row.mean,
                row.variance,
                row.samples,
                _iso(row.learning_started_ts),
                _iso(row.updated_ts),
            ),
        )

    def summaries(
        self, *, now: datetime, calibration_days: int
    ) -> dict[str, DeviceBehaviourSummary]:
        """Calibration state for every device with a bytes-out baseline.

        One query loads every row, so the Devices page never runs a query per
        device. Devices with no traffic yet have no row and are simply absent.
        """
        by_device: dict[str, list[BaselineRow]] = {}
        for row in self.load_baselines():
            by_device.setdefault(row.device_mac, []).append(row)
        return {
            mac: _summary(mac, rows, now=now, calibration_days=calibration_days)
            for mac, rows in by_device.items()
            if any(row.metric == _BYTES_OUT_METRIC for row in rows)
        }

    def device_profile(
        self, mac: str, *, now: datetime, calibration_days: int, hours: int = 24
    ) -> DeviceProfile:
        """The buckets, baselines, and events the detail page renders."""
        device = normalize_mac(mac)
        since = now - timedelta(hours=hours)
        rows = self._db.query(
            "SELECT * FROM device_baselines WHERE device_mac = ? ORDER BY metric",
            (device,),
        )
        baselines = tuple(_row_to_baseline(row) for row in rows)
        return DeviceProfile(
            summary=_summary(device, baselines, now=now, calibration_days=calibration_days),
            buckets=tuple(self.buckets(device, since=since)),
            baselines=baselines,
            recent_events=tuple(self._db.events_for_device(device, limit=20)),
        )

    def new_destinations_since(self, mac: str, *, since: datetime) -> int:
        """How many destinations this device first contacted at or after ``since``."""
        rows = self._db.query(
            "SELECT COUNT(*) AS n FROM device_destinations "
            "WHERE device_mac = ? AND first_seen_ts >= ?",
            (normalize_mac(mac), _iso(since)),
        )
        return int(rows[0]["n"])

    def seen_destinations(self, mac: str, ips: set[str] | list[str] | tuple[str, ...]) -> set[str]:
        """The subset of ``ips`` this device has contacted before."""
        addresses = _normalize_ips(ips)
        if not addresses:
            return set()
        rows = self._db.query(
            "SELECT dst_ip FROM device_destinations WHERE device_mac = ?",
            (normalize_mac(mac),),
        )
        known = {row["dst_ip"] for row in rows}
        return known.intersection(addresses)

    def record_destinations(
        self,
        mac: str,
        ips: set[str] | list[str] | tuple[str, ...],
        *,
        seen_ts: datetime,
        max_per_device: int = 500,
    ) -> None:
        """Remember ``ips`` for ``mac`` and prune beyond the per-device bound.

        ``first_seen_ts`` is written once; a repeat sighting only extends
        ``last_seen_ts``. Pruning keeps the most recently seen rows.
        """
        device = normalize_mac(mac)
        moment = _iso(seen_ts)
        for address in _normalize_ips(ips):
            self._db.execute(
                "INSERT INTO device_destinations "
                "(device_mac, dst_ip, first_seen_ts, last_seen_ts) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(device_mac, dst_ip) DO UPDATE SET "
                "last_seen_ts = excluded.last_seen_ts",
                (device, address, moment, moment),
            )
        self._db.execute(
            "DELETE FROM device_destinations WHERE device_mac = ? AND dst_ip NOT IN ("
            "SELECT dst_ip FROM device_destinations WHERE device_mac = ? "
            "ORDER BY last_seen_ts DESC, dst_ip ASC LIMIT ?)",
            (device, device, max(0, max_per_device)),
        )

    def read_status(self) -> BehaviourStatus:
        """The last published status, or fresh-install defaults."""
        raw = self._db.get_setting(_STATUS_KEY)
        if raw is None:
            return BehaviourStatus()
        try:
            return BehaviourStatus.model_validate_json(raw)
        except (ValidationError, ValueError):
            return BehaviourStatus()

    def write_status(self, status: BehaviourStatus) -> None:
        """Persist the status row the Health page reads."""
        self._db.set_setting(_STATUS_KEY, status.model_dump_json())

    def prune_activity(self, before_ts: datetime | str) -> int:
        """Delete buckets older than ``before_ts`` and return the count."""
        cutoff = _iso(before_ts) if isinstance(before_ts, datetime) else before_ts
        cursor = self._db.execute("DELETE FROM device_activity WHERE bucket_ts < ?", (cutoff,))
        return int(cursor.rowcount or 0)

    def prune_destinations(self, before_ts: datetime | str) -> int:
        """Forget destinations last seen before ``before_ts``; return the count."""
        cutoff = _iso(before_ts) if isinstance(before_ts, datetime) else before_ts
        cursor = self._db.execute(
            "DELETE FROM device_destinations WHERE last_seen_ts < ?", (cutoff,)
        )
        return int(cursor.rowcount or 0)


def _row_to_baseline(row: sqlite3.Row) -> BaselineRow:
    """Rebuild a :class:`BaselineRow` from a database row."""
    return BaselineRow(
        device_mac=str(row["device_mac"]),
        metric=str(row["metric"]),
        mean=float(row["mean"]),
        variance=float(row["variance"]),
        samples=int(row["samples"]),
        learning_started_ts=_parse_ts(str(row["learning_started_ts"])),
        updated_ts=_parse_ts(str(row["updated_ts"])),
    )


def _summary(
    mac: str,
    baselines: tuple[BaselineRow, ...] | list[BaselineRow],
    *,
    now: datetime,
    calibration_days: int,
) -> DeviceBehaviourSummary:
    """Build the calibration summary from a device's baseline rows."""
    # Local import: ``baseline`` depends on this module for ``BaselineRow``, so a
    # module-level import here would be circular.
    from gilgamesh.behaviour.baseline import MIN_SAMPLES

    row = next((item for item in baselines if item.metric == _BYTES_OUT_METRIC), None)
    if row is None:
        return DeviceBehaviourSummary(
            mac=mac,
            state="none",
            days_learning=0,
            calibration_days=calibration_days,
            samples=0,
        )
    elapsed = now - row.learning_started_ts
    days_learning = min(max(0, calibration_days), max(0, elapsed.days))
    calibrated = row.samples >= MIN_SAMPLES and (
        calibration_days <= 0 or elapsed >= timedelta(days=calibration_days)
    )
    return DeviceBehaviourSummary(
        mac=mac,
        state="calibrated" if calibrated else "learning",
        days_learning=days_learning,
        calibration_days=calibration_days,
        samples=row.samples,
        updated_ts=row.updated_ts,
    )


def _normalize_ips(ips: set[str] | list[str] | tuple[str, ...]) -> list[str]:
    normalized: set[str] = set()
    for value in ips:
        try:
            normalized.add(str(ipaddress.ip_address(value.strip())))
        except ValueError:
            continue
    return sorted(normalized)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("behaviour timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)
