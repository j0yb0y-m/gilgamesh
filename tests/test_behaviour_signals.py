"""Per-device volume-spike and new-destination signals."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from gilgamesh.behaviour.baseline import Baseline
from gilgamesh.behaviour.signals import (
    EXCLUDED_BEACON_PORTS,
    SignalHit,
    beaconing,
    is_beacon_candidate,
    new_destination_burst,
    volume_spike,
)
from gilgamesh.models import Severity

NOW = datetime(2026, 11, 1, 2, 0, tzinfo=UTC)


def _number(value: object) -> float:
    assert isinstance(value, int | float)
    return float(value)


def test_volume_spike_fires_on_a_large_ratio_and_z_score() -> None:
    baseline = Baseline(
        mean=math.log1p(4_000_000), variance=0.04, samples=100, learning_started_ts=NOW
    )

    hit = volume_spike(
        direction="out",
        observed_bytes=1_800_000_000,
        baseline=baseline,
        z_threshold=5.0,
        min_bytes=10_000_000,
        min_ratio=10.0,
    )

    assert isinstance(hit, SignalHit)
    assert hit.severity is Severity.MEDIUM
    assert hit.signal == "volume_spike"
    assert _number(hit.details["ratio"]) >= 400
    assert hit.details["observed_bytes"] == 1_800_000_000
    assert hit.details["direction"] == "out"
    assert hit.details["samples"] == 100
    assert hit.details["baseline_mean_bytes"] == 4_000_000
    assert hit.details["baseline_std_log"] == pytest.approx(0.2)
    assert _number(hit.details["z_score"]) >= 5.0


def test_volume_spike_respects_each_absolute_floor() -> None:
    baseline = Baseline(
        mean=math.log1p(4_000_000), variance=0.04, samples=100, learning_started_ts=NOW
    )

    def spike(
        observed_bytes: int, *, z_threshold: float = 5.0, min_ratio: float = 10.0
    ) -> SignalHit | None:
        return volume_spike(
            direction="out",
            observed_bytes=observed_bytes,
            baseline=baseline,
            z_threshold=z_threshold,
            min_bytes=10_000_000,
            min_ratio=min_ratio,
        )

    assert spike(9_000_000) is None
    assert spike(1_800_000_000, min_ratio=500) is None
    assert spike(1_800_000_000, z_threshold=100) is None


def test_volume_spike_ignores_zero_bytes_and_uses_a_ratio_denominator_of_one() -> None:
    baseline = Baseline(mean=0.0, variance=0.0, samples=100, learning_started_ts=NOW)

    assert (
        volume_spike(
            direction="in",
            observed_bytes=0,
            baseline=baseline,
            z_threshold=5.0,
            min_bytes=0,
            min_ratio=0.0,
        )
        is None
    )
    hit = volume_spike(
        direction="in",
        observed_bytes=1_000_000,
        baseline=baseline,
        z_threshold=5.0,
        min_bytes=1,
        min_ratio=1.0,
    )
    assert hit is not None
    assert hit.details["ratio"] == 1_000_000
    assert hit.details["baseline_mean_bytes"] == 0


def test_new_destination_burst_fires_at_the_baseline_threshold() -> None:
    baseline = Baseline(mean=10.0, variance=4.0, samples=100, learning_started_ts=NOW)

    assert new_destination_burst(new_count=17, baseline=baseline) is None
    hit = new_destination_burst(new_count=18, baseline=baseline)

    assert hit is not None
    assert hit.signal == "new_destinations"
    assert hit.severity is Severity.MEDIUM
    assert hit.details["new_destinations"] == 18
    assert hit.details["threshold"] == pytest.approx(18.0)
    assert hit.details["baseline_mean"] == 10.0


def test_new_destination_burst_uses_min_new_when_the_baseline_is_quiet() -> None:
    quiet = Baseline(mean=0.0, variance=0.0, samples=100, learning_started_ts=NOW)

    assert new_destination_burst(new_count=7, baseline=quiet) is None
    assert new_destination_burst(new_count=8, baseline=quiet) is not None


def test_new_destination_burst_needs_a_baseline_and_positive_count() -> None:
    assert new_destination_burst(new_count=100, baseline=None) is None
    assert (
        new_destination_burst(
            new_count=0,
            baseline=Baseline(0.0, 0.0, 100, NOW),
        )
        is None
    )


def test_beaconing_fires_on_regular_small_connections() -> None:
    start = datetime(2026, 11, 1, 2, 0, tzinfo=UTC)
    stamps = [start + timedelta(seconds=60 * i + (i % 2)) for i in range(8)]

    hit = beaconing(
        dst_ip="203.0.113.9",
        dst_port=443,
        timestamps=stamps,
        total_bytes=40_000,
    )

    assert hit is not None
    assert hit.signal == "beaconing"
    assert hit.severity is Severity.LOW
    assert hit.dst_ip == "203.0.113.9"
    assert hit.details["connections"] == 8
    assert _number(hit.details["cov"]) <= 0.15
    assert hit.details["dst_ip"] == "203.0.113.9"
    assert hit.details["dst_port"] == 443
    assert hit.details["total_bytes"] == 40_000
    assert _number(hit.details["mean_interval_s"]) > 0


def test_beaconing_rejects_jitter_and_large_transfers() -> None:
    start = datetime(2026, 11, 1, 2, 0, tzinfo=UTC)
    regular = [start + timedelta(seconds=60 * i) for i in range(8)]
    jittered = [
        start + timedelta(seconds=offset) for offset in (0, 60, 240, 300, 600, 660, 1_200, 1_260)
    ]

    assert (
        beaconing(dst_ip="203.0.113.9", dst_port=443, timestamps=jittered, total_bytes=1_000)
        is None
    )
    assert (
        beaconing(
            dst_ip="203.0.113.9",
            dst_port=443,
            timestamps=regular,
            total_bytes=2_000_000,
        )
        is None
    )


def test_beaconing_needs_enough_connections_and_intervals() -> None:
    start = datetime(2026, 11, 1, 2, 0, tzinfo=UTC)
    seven = [start + timedelta(seconds=60 * i) for i in range(7)]

    assert beaconing(dst_ip="203.0.113.9", dst_port=443, timestamps=seven, total_bytes=1) is None
    assert (
        beaconing(
            dst_ip="203.0.113.9",
            dst_port=443,
            timestamps=[start],
            total_bytes=1,
            min_connections=2,
        )
        is None
    )


def test_beaconing_sorts_out_of_order_timestamps() -> None:
    start = datetime(2026, 11, 1, 2, 0, tzinfo=UTC)
    stamps = [start + timedelta(seconds=60 * i) for i in range(8)]
    shuffled = list(reversed(stamps))

    hit = beaconing(dst_ip="203.0.113.9", dst_port=443, timestamps=shuffled, total_bytes=1)

    assert hit is not None
    assert hit.details["connections"] == 8


def test_beacon_candidate_excludes_chatty_ports_and_lan_destinations() -> None:
    assert not is_beacon_candidate(dst_port=None, dst_ip="203.0.113.9", internal=False)
    assert not is_beacon_candidate(dst_port=123, dst_ip="203.0.113.9", internal=False)
    assert not is_beacon_candidate(dst_port=443, dst_ip="10.0.0.5", internal=True)
    assert is_beacon_candidate(dst_port=443, dst_ip="203.0.113.9", internal=False)
    assert frozenset({67, 68, 123, 1900, 5353}) == EXCLUDED_BEACON_PORTS
