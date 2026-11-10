"""Aggregate EVE facts into bounded 15-minute per-device buckets.

The aggregator is the only place that knows how a flow maps to devices. It keeps a
bounded in-memory window, writes finalized buckets through ``BehaviourStore``, scores
each bucket against the device's own pre-update baseline, and emits at most one
event per ``(device, signal)`` per hour.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from gilgamesh.behaviour.attribution import DeviceMap
from gilgamesh.behaviour.baseline import (
    BYTES_IN_LOG,
    BYTES_OUT_LOG,
    DNS_QUERIES,
    NEW_DESTINATIONS,
    UNIQUE_DST,
    Baseline,
)
from gilgamesh.behaviour.eve import DnsFact, FlowFact
from gilgamesh.behaviour.signals import (
    SignalHit,
    beaconing,
    is_beacon_candidate,
    new_destination_burst,
    volume_spike,
)
from gilgamesh.behaviour.store import ActivityBucket, BaselineRow, BehaviourStatus, BehaviourStore
from gilgamesh.models import Event, EventType
from gilgamesh.rules import RuleConfigService

Clock = Callable[[], datetime]

_DEFAULT_BUCKET_SECONDS = 900
_DEFAULT_GRACE_SECONDS = 30
_MAX_BEACON_KEYS = 200
_MAX_BEACON_TIMESTAMPS = 64
_EPISODE_WINDOW = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class BehaviourParams:
    """The owner-tunable thresholds for the three signals."""

    z_threshold: float = 5.0
    min_bytes: int = 10_000_000
    min_ratio: float = 10.0
    min_new: int = 8
    min_connections: int = 8
    max_cov: float = 0.15
    max_bytes: int = 1_000_000

    @classmethod
    def from_rules(cls, rules: RuleConfigService) -> BehaviourParams:
        """Read the owner's current values from the rule catalogue."""
        volume = rules.effective_params("behaviour.volume_spike")
        destinations = rules.effective_params("behaviour.new_destinations")
        beacons = rules.effective_params("behaviour.beaconing")
        return cls(
            z_threshold=_as_float(volume["z_threshold"]),
            min_bytes=_as_int(volume["min_bytes"]),
            min_ratio=_as_float(volume["min_ratio"]),
            min_new=_as_int(destinations["min_new"]),
            min_connections=_as_int(beacons["min_connections"]),
            max_cov=_as_float(beacons["max_cov"]),
            max_bytes=_as_int(beacons["max_bytes"]),
        )


@dataclass(slots=True)
class _Bucket:
    """The in-memory totals for one device and one bucket."""

    dsts: set[str] = field(default_factory=set[str])
    dns_names: set[str] = field(default_factory=set[str])
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    flows: int = 0
    dns_queries: int = 0


@dataclass(slots=True)
class _Episode:
    """The per-(device, signal) cadence state."""

    last_bucket: datetime | None = None
    consecutive: int = 0
    last_emitted: datetime | None = None


class BehaviourAggregator:
    """Turn flow and DNS facts into per-device activity buckets and events."""

    def __init__(
        self,
        store: BehaviourStore,
        devices: DeviceMap,
        *,
        calibration_days: int = 7,
        bucket_seconds: int = _DEFAULT_BUCKET_SECONDS,
        grace_seconds: int = _DEFAULT_GRACE_SECONDS,
        max_devices: int = 1000,
        max_bucket_destinations: int = 5000,
        params: BehaviourParams | None = None,
        clock: Clock | None = None,
    ) -> None:
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        self._store = store
        self._devices = devices
        self._calibration_days = calibration_days
        self._bucket_seconds = bucket_seconds
        self._grace = timedelta(seconds=max(0, grace_seconds))
        self._max_devices = max(0, max_devices)
        self._max_bucket_destinations = max(0, max_bucket_destinations)
        self._params = params or BehaviourParams()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._windows: dict[str, dict[datetime, _Bucket]] = {}
        self._flushed_through: dict[str, datetime] = {}
        self._baselines: dict[tuple[str, str], Baseline] = {
            (row.device_mac, row.metric): Baseline.from_row(row) for row in store.load_baselines()
        }
        self._episodes: dict[tuple[str, str], _Episode] = {}
        self._beacons: dict[str, dict[tuple[str, int], deque[tuple[datetime, int]]]] = {}
        self._flows_seen = 0
        self._dns_seen = 0
        self._unknown_ip_flows = 0
        self._ipv6_flows = 0
        self._devices_dropped = 0
        self._late_buckets = 0
        self._last_flow_ts: datetime | None = None
        self._last_dns_ts: datetime | None = None
        self._last_flush_ts: datetime | None = None

    @property
    def tracked_devices(self) -> int:
        """How many devices currently hold a buffered bucket."""
        return len(self._windows)

    @property
    def status(self) -> BehaviourStatus:
        """A snapshot for the Health page and the service's periodic publish."""
        return BehaviourStatus(
            updated_ts=self._clock(),
            last_flow_ts=self._last_flow_ts,
            last_dns_ts=self._last_dns_ts,
            flows_seen=self._flows_seen,
            dns_seen=self._dns_seen,
            unknown_ip_flows=self._unknown_ip_flows,
            ipv6_flows=self._ipv6_flows,
            devices_tracked=len(self._windows),
            devices_dropped=self._devices_dropped,
            late_buckets=self._late_buckets,
            last_flush_ts=self._last_flush_ts,
        )

    def record(self, fact: FlowFact | DnsFact) -> None:
        """Attribute one fact and fold it into the matching buckets."""
        if isinstance(fact, FlowFact):
            self._record_flow(fact)
        else:
            self._record_dns(fact)

    def flush(self, now: datetime | None = None) -> list[Event]:
        """Write every bucket whose grace window has passed and return new events."""
        moment = now or self._clock()
        cutoff = moment - self._grace
        events: list[Event] = []
        for mac, buckets in list(self._windows.items()):
            ready = [
                bucket_ts
                for bucket_ts in buckets
                if bucket_ts + timedelta(seconds=self._bucket_seconds) <= cutoff
            ]
            for bucket_ts in sorted(ready):
                events.extend(self._write(mac, bucket_ts, buckets.pop(bucket_ts)))
            if not buckets:
                del self._windows[mac]
        self._last_flush_ts = moment
        return events

    def close(self) -> list[Event]:
        """Write every buffered bucket, regardless of the grace window."""
        events: list[Event] = []
        for mac, buckets in list(self._windows.items()):
            for bucket_ts in sorted(buckets):
                events.extend(self._write(mac, bucket_ts, buckets[bucket_ts]))
        self._windows.clear()
        self._last_flush_ts = self._clock()
        return events

    def _record_flow(self, fact: FlowFact) -> None:
        self._flows_seen += 1
        self._last_flow_ts = fact.ts

        if self._devices.is_ipv6(fact.src_ip) or self._devices.is_ipv6(fact.dst_ip):
            self._unknown_ip_flows += 1
            self._ipv6_flows += 1
            return

        src_mac = self._devices.lookup(fact.src_ip)
        dst_mac = self._devices.lookup(fact.dst_ip)
        bucket_ts = self._floor(fact.ts)

        if src_mac is None and dst_mac is None:
            self._unknown_ip_flows += 1
            return

        late = False
        if src_mac is not None:
            dst_external = self._devices.is_external(fact.dst_ip)
            late |= self._add(
                src_mac,
                bucket_ts,
                bytes_in=fact.bytes_toclient,
                bytes_out=fact.bytes_toserver,
                packets_in=fact.pkts_toclient,
                packets_out=fact.pkts_toserver,
                flows=1,
                dst=fact.dst_ip if dst_external else None,
            )
            if dst_external and is_beacon_candidate(
                dst_port=fact.dst_port,
                dst_ip=fact.dst_ip,
                internal=False,
            ):
                self._remember_beacon(
                    src_mac,
                    fact.dst_ip,
                    fact.dst_port,
                    fact.ts,
                    fact.bytes_toserver,
                    bucket_ts + timedelta(seconds=self._bucket_seconds),
                )

        if dst_mac is not None and dst_mac != src_mac:
            late |= self._add(
                dst_mac,
                bucket_ts,
                bytes_in=fact.bytes_toserver,
                bytes_out=fact.bytes_toclient,
                packets_in=fact.pkts_toserver,
                packets_out=fact.pkts_toclient,
                flows=1,
            )

        if late:
            self._late_buckets += 1

    def _record_dns(self, fact: DnsFact) -> None:
        self._dns_seen += 1
        self._last_dns_ts = fact.ts

        if fact.is_response:
            return
        mac = self._devices.lookup(fact.src_ip)
        if mac is None:
            return
        late = self._add(
            mac,
            self._floor(fact.ts),
            dns_queries=1,
            dns_names=fact.names,
        )
        if late:
            self._late_buckets += 1

    def _remember_beacon(
        self,
        mac: str,
        dst_ip: str,
        dst_port: int | None,
        ts: datetime,
        size: int,
        bucket_end: datetime,
    ) -> None:
        if dst_port is None:
            return
        by_key = self._beacons.get(mac)
        if by_key is None:
            by_key = {}
            self._beacons[mac] = by_key
        key = (dst_ip, dst_port)
        entries = by_key.get(key)
        if entries is None:
            if len(by_key) >= _MAX_BEACON_KEYS:
                return
            entries = deque[tuple[datetime, int]](maxlen=_MAX_BEACON_TIMESTAMPS)
            by_key[key] = entries
        cutoff = bucket_end - _EPISODE_WINDOW
        while entries and entries[0][0] <= cutoff:
            entries.popleft()
        entries.append((ts, max(0, size)))

    def _add(
        self,
        mac: str,
        bucket_ts: datetime,
        *,
        bytes_in: int = 0,
        bytes_out: int = 0,
        packets_in: int = 0,
        packets_out: int = 0,
        flows: int = 0,
        dst: str | None = None,
        dns_queries: int = 0,
        dns_names: tuple[str, ...] = (),
    ) -> bool:
        """Add to a device's bucket, writing immediately when it is already flushed.

        Returns ``True`` when the fact was late, so the caller can count it once.
        """
        last = self._flushed_through.get(mac)
        if last is not None and bucket_ts <= last:
            self._write_late(
                mac,
                bucket_ts,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
                packets_in=packets_in,
                packets_out=packets_out,
                flows=flows,
                dst=dst,
                dns_queries=dns_queries,
                dns_names=dns_names,
            )
            return True

        buckets = self._windows.get(mac)
        if buckets is None:
            if len(self._windows) >= self._max_devices:
                self._devices_dropped += 1
                return False
            buckets = {}
            self._windows[mac] = buckets
        bucket = buckets.setdefault(bucket_ts, _Bucket())
        bucket.bytes_in += bytes_in
        bucket.bytes_out += bytes_out
        bucket.packets_in += packets_in
        bucket.packets_out += packets_out
        bucket.flows += flows
        bucket.dns_queries += dns_queries
        bucket.dns_names.update(dns_names)
        if dst is not None and len(bucket.dsts) < self._max_bucket_destinations:
            bucket.dsts.add(dst)
        return False

    def _write_late(
        self,
        mac: str,
        bucket_ts: datetime,
        *,
        bytes_in: int,
        bytes_out: int,
        packets_in: int,
        packets_out: int,
        flows: int,
        dst: str | None,
        dns_queries: int,
        dns_names: tuple[str, ...],
    ) -> None:
        """Write one late fact additively, without reopening or scoring the bucket."""
        self._store.write_bucket(
            ActivityBucket(
                device_mac=mac,
                bucket_ts=bucket_ts,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
                packets_in=packets_in,
                packets_out=packets_out,
                flows=flows,
                unique_dst=1 if dst is not None else 0,
                dns_queries=dns_queries,
                dns_unique_names=len(set(dns_names)),
            ),
            additive=True,
        )

    def _write(self, mac: str, bucket_ts: datetime, bucket: _Bucket) -> list[Event]:
        bucket_end = bucket_ts + timedelta(seconds=self._bucket_seconds)
        new_count = len(bucket.dsts - self._store.seen_destinations(mac, bucket.dsts))
        events = self._score(mac, bucket_ts, bucket_end, bucket, new_count)
        self._store.write_bucket(
            ActivityBucket(
                device_mac=mac,
                bucket_ts=bucket_ts,
                bytes_in=bucket.bytes_in,
                bytes_out=bucket.bytes_out,
                packets_in=bucket.packets_in,
                packets_out=bucket.packets_out,
                flows=bucket.flows,
                unique_dst=len(bucket.dsts),
                dns_queries=bucket.dns_queries,
                dns_unique_names=len(bucket.dns_names),
            )
        )
        self._update_baselines(mac, bucket, new_count, bucket_end)
        self._store.record_destinations(mac, bucket.dsts, seen_ts=bucket_end)
        self._flushed_through[mac] = max(bucket_ts, self._flushed_through.get(mac, bucket_ts))
        return events

    def _score(
        self,
        mac: str,
        bucket_ts: datetime,
        bucket_end: datetime,
        bucket: _Bucket,
        new_count: int,
    ) -> list[Event]:
        out_baseline = self._baselines.get((mac, BYTES_OUT_LOG))
        if out_baseline is None or not out_baseline.is_calibrated(
            bucket_end, days=self._calibration_days
        ):
            return []

        events: list[Event] = []
        hit = volume_spike(
            direction="out",
            observed_bytes=bucket.bytes_out,
            baseline=out_baseline,
            z_threshold=self._params.z_threshold,
            min_bytes=self._params.min_bytes,
            min_ratio=self._params.min_ratio,
        )
        if hit is not None:
            events.extend(self._emit(mac, hit, bucket_ts, bucket_end))

        in_baseline = self._baselines.get((mac, BYTES_IN_LOG))
        if in_baseline is not None:
            hit = volume_spike(
                direction="in",
                observed_bytes=bucket.bytes_in,
                baseline=in_baseline,
                z_threshold=self._params.z_threshold,
                min_bytes=self._params.min_bytes,
                min_ratio=self._params.min_ratio,
            )
            if hit is not None:
                events.extend(self._emit(mac, hit, bucket_ts, bucket_end))

        hit = new_destination_burst(
            new_count=new_count,
            baseline=self._baselines.get((mac, NEW_DESTINATIONS)),
            min_new=self._params.min_new,
        )
        if hit is not None:
            events.extend(self._emit(mac, hit, bucket_ts, bucket_end))

        events.extend(self._score_beacons(mac, bucket_ts, bucket_end))
        return events

    def _score_beacons(self, mac: str, bucket_ts: datetime, bucket_end: datetime) -> list[Event]:
        events: list[Event] = []
        for (dst_ip, dst_port), entries in self._beacons.get(mac, {}).items():
            window = [
                (ts, size)
                for ts, size in entries
                if bucket_end - _EPISODE_WINDOW < ts <= bucket_end
            ]
            hit = beaconing(
                dst_ip=dst_ip,
                dst_port=dst_port,
                timestamps=[ts for ts, _size in window],
                total_bytes=sum(size for _ts, size in window),
                min_connections=self._params.min_connections,
                max_cov=self._params.max_cov,
                max_bytes=self._params.max_bytes,
            )
            if hit is not None:
                events.extend(self._emit(mac, hit, bucket_ts, bucket_end))
        return events

    def _update_baselines(self, mac: str, bucket: _Bucket, new_count: int, now: datetime) -> None:
        values = {
            BYTES_OUT_LOG: math.log1p(bucket.bytes_out),
            BYTES_IN_LOG: math.log1p(bucket.bytes_in),
            UNIQUE_DST: float(len(bucket.dsts)),
            NEW_DESTINATIONS: float(new_count),
            DNS_QUERIES: float(bucket.dns_queries),
        }
        for metric, value in values.items():
            key = (mac, metric)
            current = self._baselines.get(key)
            updated = (
                Baseline.initial(value, now=now)
                if current is None
                else current.updated(value, now=now)
            )
            self._baselines[key] = updated
            self._store.upsert_baseline(
                BaselineRow(
                    device_mac=mac,
                    metric=metric,
                    mean=updated.mean,
                    variance=updated.variance,
                    samples=updated.samples,
                    learning_started_ts=updated.learning_started_ts,
                    updated_ts=now,
                )
            )

    def _emit(
        self, mac: str, hit: SignalHit, bucket_ts: datetime, bucket_end: datetime
    ) -> list[Event]:
        device = self._devices.record(mac)
        if device is None:
            return []
        consecutive = self._episode(mac, hit.signal, bucket_ts, bucket_end)
        if consecutive is None:
            return []
        label = device.hostname or device.mac
        details: dict[str, object] = {
            "signal": hit.signal,
            "reason": hit.signal,
            "device_label": label,
            "window_start": bucket_ts.isoformat(),
            "window_end": bucket_end.isoformat(),
            "consecutive_buckets": consecutive,
            **hit.details,
        }
        return [
            Event(
                type=EventType.BEHAVIOUR_ANOMALY,
                severity=hit.severity,
                detector=f"behaviour.{hit.signal}",
                summary=_summary(label, hit),
                src_mac=device.mac,
                src_ip=device.ips[0] if device.ips else None,
                dst_ip=hit.dst_ip,
                details=details,
            )
        ]

    def _episode(
        self, mac: str, signal: str, bucket_ts: datetime, bucket_end: datetime
    ) -> int | None:
        state = self._episodes.setdefault((mac, signal), _Episode())
        if state.last_bucket is not None and bucket_ts - state.last_bucket == timedelta(
            seconds=self._bucket_seconds
        ):
            state.consecutive += 1
        else:
            state.consecutive = 1
        state.last_bucket = bucket_ts
        if state.last_emitted is not None and bucket_end - state.last_emitted < _EPISODE_WINDOW:
            return None
        state.last_emitted = bucket_end
        return state.consecutive

    def _floor(self, moment: datetime) -> datetime:
        epoch = int(moment.timestamp())
        return datetime.fromtimestamp(epoch - epoch % self._bucket_seconds, UTC)


def _as_float(value: int | float | bool | str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"expected a number, got {value!r}")
    return float(value)


def _as_int(value: int | float | bool | str) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"expected a number, got {value!r}")
    return int(value)


def _summary(label: str, hit: SignalHit) -> str:
    if hit.signal == "volume_spike":
        verb = "uploaded" if hit.details.get("direction") == "out" else "downloaded"
        return f"{label} {verb} {hit.details['ratio']}x its normal amount in the last 15 minutes."
    if hit.signal == "new_destinations":
        return (
            f"{label} contacted {hit.details['new_destinations']} new external hosts "
            "in the last 15 minutes."
        )
    return (
        f"{label} made {hit.details['connections']} regular connections to "
        f"{hit.details['dst_ip']} every {hit.details['mean_interval_s']}s."
    )


__all__ = ["BehaviourAggregator", "BehaviourParams"]
