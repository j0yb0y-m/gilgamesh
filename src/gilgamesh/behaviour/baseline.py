"""EWMA baselines for per-device behaviour metrics.

The baseline is deliberately simple: one mean and one variance per device/metric,
updated with a fixed-weight EWMA. It is not a model of the device; it is a slow
memory that makes a sudden departure visible. The first sample seeds the mean, and
a metric is only trusted after both the calibration time and a minimum number of
samples have passed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta

from gilgamesh.behaviour.store import BaselineRow

ALPHA = 0.1
MIN_SAMPLES = 20

BYTES_OUT_LOG = "bytes_out_log"
BYTES_IN_LOG = "bytes_in_log"
UNIQUE_DST = "unique_dst"
NEW_DESTINATIONS = "new_destinations"
DNS_QUERIES = "dns_queries"

_LOG_METRICS = frozenset({BYTES_OUT_LOG, BYTES_IN_LOG})
_COUNT_METRICS = frozenset({UNIQUE_DST, NEW_DESTINATIONS, DNS_QUERIES})
_COUNT_FLOOR = 0.5
_VOLUME_FLOOR = 0.05


@dataclass(frozen=True, slots=True)
class Baseline:
    """One device/metric EWMA state."""

    mean: float
    variance: float
    samples: int
    learning_started_ts: datetime

    @classmethod
    def initial(cls, value: float, *, now: datetime) -> Baseline:
        """Seed a baseline from the first observed value."""
        return cls(mean=float(value), variance=0.0, samples=1, learning_started_ts=now)

    @classmethod
    def from_row(cls, row: BaselineRow) -> Baseline:
        """Rebuild a baseline from its persisted row."""
        return cls(
            mean=row.mean,
            variance=row.variance,
            samples=row.samples,
            learning_started_ts=row.learning_started_ts,
        )

    def updated(self, value: float, *, now: datetime, alpha: float = ALPHA) -> Baseline:
        """Return a new baseline with one EWMA update."""
        if self.samples <= 0:
            return Baseline.initial(value, now=now)
        old_mean = self.mean
        mean = (1.0 - alpha) * old_mean + alpha * value
        variance = max(
            0.0,
            (1.0 - alpha) * (self.variance + alpha * (value - old_mean) ** 2),
        )
        return Baseline(
            mean=mean,
            variance=variance,
            samples=self.samples + 1,
            learning_started_ts=self.learning_started_ts,
        )

    def z_score(self, value: float, *, floor: float) -> float:
        """How many standard deviations ``value`` is from the mean."""
        return (value - self.mean) / max(math.sqrt(self.variance), floor)

    def is_calibrated(self, now: datetime, *, days: int, min_samples: int = MIN_SAMPLES) -> bool:
        """Whether the baseline has both enough history and enough samples."""
        if self.samples < min_samples:
            return False
        if days == 0:
            return True
        return now - self.learning_started_ts >= timedelta(days=days)

    def normal_value(self) -> float:
        """The mean back in the metric's natural units (for log metrics)."""
        return math.expm1(self.mean)


def metric_is_log(metric: str) -> bool:
    """Whether ``metric`` is stored as ``log1p(value)``."""
    return metric in _LOG_METRICS


def metric_floor(metric: str) -> float:
    """The smallest standard deviation used by :meth:`Baseline.z_score`."""
    if metric in _LOG_METRICS:
        return _VOLUME_FLOOR
    if metric in _COUNT_METRICS:
        return _COUNT_FLOOR
    raise ValueError(f"unknown behaviour metric: {metric!r}")


__all__ = [
    "ALPHA",
    "BYTES_IN_LOG",
    "BYTES_OUT_LOG",
    "DNS_QUERIES",
    "MIN_SAMPLES",
    "NEW_DESTINATIONS",
    "UNIQUE_DST",
    "Baseline",
    "metric_floor",
    "metric_is_log",
]
