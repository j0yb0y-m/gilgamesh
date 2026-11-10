"""Pure scoring functions for the three behaviour signals.

Each function returns a :class:`SignalHit` or ``None``; none of them touch the
database or the clock. Keeping the arithmetic pure is what makes the thresholds
easy to test and the aggregator's event logic separate.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from datetime import datetime
from statistics import pstdev

from gilgamesh.behaviour.baseline import Baseline
from gilgamesh.models import Severity

#: Protocols whose regular chatter is normal and would drown a beacon signal.
EXCLUDED_BEACON_PORTS = frozenset({67, 68, 123, 1900, 5353})

_VOLUME_FLOOR = 0.05


@dataclass(frozen=True, slots=True)
class SignalHit:
    """One signal's verdict, ready for the aggregator to turn into an event."""

    signal: str
    severity: Severity
    details: dict[str, object] = field(default_factory=dict[str, object])
    dst_ip: str | None = None


def volume_spike(
    *,
    direction: str,
    observed_bytes: int,
    baseline: Baseline,
    z_threshold: float,
    min_bytes: int,
    min_ratio: float,
) -> SignalHit | None:
    """Fire when a bucket's volume is both absolutely and relatively large."""
    if observed_bytes <= 0:
        return None

    z = (math.log1p(observed_bytes) - baseline.mean) / max(
        math.sqrt(baseline.variance), _VOLUME_FLOOR
    )
    ratio = observed_bytes / max(math.expm1(baseline.mean), 1.0)
    if z < z_threshold or observed_bytes < min_bytes or ratio < min_ratio:
        return None

    return SignalHit(
        signal="volume_spike",
        severity=Severity.MEDIUM,
        details={
            "direction": direction,
            "observed_bytes": observed_bytes,
            "baseline_mean_bytes": int(math.expm1(baseline.mean)),
            "baseline_std_log": round(math.sqrt(baseline.variance), 2),
            "z_score": round(z, 2),
            "ratio": round(ratio, 2),
            "samples": baseline.samples,
        },
    )


def new_destination_burst(
    *,
    new_count: int,
    baseline: Baseline | None,
    min_new: int = 8,
    sigma: float = 4.0,
) -> SignalHit | None:
    """Fire when a device contacts more new external hosts than its own normal."""
    if baseline is None or new_count <= 0:
        return None
    threshold = max(min_new, baseline.mean + sigma * math.sqrt(baseline.variance))
    if new_count < threshold:
        return None

    return SignalHit(
        signal="new_destinations",
        severity=Severity.MEDIUM,
        details={
            "new_destinations": new_count,
            "threshold": round(threshold, 2),
            "baseline_mean": round(baseline.mean, 2),
            "sigma": sigma,
            "samples": baseline.samples,
        },
    )


def is_beacon_candidate(*, dst_port: int | None, dst_ip: str, internal: bool) -> bool:
    """Whether a flow is worth keeping in the beaconing window."""
    if dst_port is None or dst_port in EXCLUDED_BEACON_PORTS:
        return False
    return not internal


def beaconing(
    *,
    dst_ip: str,
    dst_port: int | None,
    timestamps: list[datetime] | tuple[datetime, ...],
    total_bytes: int,
    min_connections: int = 8,
    max_cov: float = 0.15,
    max_bytes: int = 1_000_000,
) -> SignalHit | None:
    """Fire on small, regularly spaced connections to one external endpoint."""
    if len(timestamps) < min_connections or total_bytes > max_bytes:
        return None

    ordered = sorted(timestamps)
    intervals = [
        (later - earlier).total_seconds() for earlier, later in itertools.pairwise(ordered)
    ]
    if len(intervals) < 2:
        return None
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return None
    cov = pstdev(intervals) / mean
    if cov > max_cov:
        return None

    return SignalHit(
        signal="beaconing",
        severity=Severity.LOW,
        dst_ip=dst_ip,
        details={
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "connections": len(ordered),
            "cov": round(cov, 3),
            "mean_interval_s": round(mean, 1),
            "total_bytes": total_bytes,
        },
    )


__all__ = [
    "EXCLUDED_BEACON_PORTS",
    "SignalHit",
    "beaconing",
    "is_beacon_candidate",
    "new_destination_burst",
    "volume_spike",
]
