"""EWMA baselines and the calibration gate."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from gilgamesh.behaviour.baseline import (
    ALPHA,
    BYTES_IN_LOG,
    BYTES_OUT_LOG,
    DNS_QUERIES,
    MIN_SAMPLES,
    NEW_DESTINATIONS,
    UNIQUE_DST,
    Baseline,
    metric_floor,
    metric_is_log,
)
from gilgamesh.behaviour.store import BaselineRow

NOW = datetime(2026, 11, 1, 2, 0, tzinfo=UTC)


def test_initial_sample_sets_mean_and_starts_calibration_clock() -> None:
    baseline = Baseline.initial(3.0, now=NOW)

    assert (baseline.mean, baseline.variance, baseline.samples) == (3.0, 0.0, 1)
    assert baseline.learning_started_ts == NOW


def test_ewma_update_uses_the_documented_formula() -> None:
    baseline = Baseline.initial(0.0, now=NOW).updated(10.0, now=NOW)

    assert baseline.mean == pytest.approx(1.0)
    assert baseline.variance == pytest.approx(9.0)
    assert baseline.samples == 2


def test_variance_never_goes_negative() -> None:
    baseline = Baseline(5.0, 0.0, 10, NOW).updated(5.0, now=NOW)

    assert baseline.variance == 0.0


def test_calibration_needs_both_time_and_twenty_samples() -> None:
    baseline = Baseline(1.0, 1.0, 19, NOW)

    assert not baseline.is_calibrated(NOW + timedelta(days=7), days=7)
    assert not baseline.is_calibrated(NOW + timedelta(days=6), days=7, min_samples=19)
    assert baseline.updated(1.0, now=NOW).is_calibrated(NOW + timedelta(days=7), days=7)
    assert baseline.updated(1.0, now=NOW).is_calibrated(NOW, days=0)


def test_calibration_defaults_to_the_shipped_minimum() -> None:
    assert MIN_SAMPLES == 20
    assert Baseline(1.0, 1.0, 20, NOW).is_calibrated(NOW, days=0)
    assert not Baseline(1.0, 1.0, 19, NOW).is_calibrated(NOW, days=0)


def test_log_metric_normal_value_uses_expm1() -> None:
    assert metric_is_log(BYTES_OUT_LOG)
    assert metric_is_log(BYTES_IN_LOG)
    assert not metric_is_log(UNIQUE_DST)
    assert Baseline(2.0, 0.0, 30, NOW).normal_value() == pytest.approx(math.expm1(2.0))


def test_metric_floors_and_unknown_metric() -> None:
    assert metric_floor(UNIQUE_DST) == 0.5
    assert metric_floor(NEW_DESTINATIONS) == 0.5
    assert metric_floor(DNS_QUERIES) == 0.5
    assert metric_floor(BYTES_OUT_LOG) == 0.05
    assert metric_floor(BYTES_IN_LOG) == 0.05
    with pytest.raises(ValueError):
        metric_floor("not_a_metric")


def test_z_score_uses_the_floor_and_zero_at_the_mean() -> None:
    baseline = Baseline(2.0, 0.0, 30, NOW)

    assert baseline.z_score(2.0, floor=0.5) == 0.0
    assert baseline.z_score(3.0, floor=0.5) == pytest.approx(2.0)
    assert baseline.z_score(1.0, floor=0.5) == pytest.approx(-2.0)


def test_from_row_round_trips() -> None:
    row = BaselineRow(
        device_mac="aa:bb:cc:dd:ee:01",
        metric=BYTES_OUT_LOG,
        mean=1.5,
        variance=0.25,
        samples=12,
        learning_started_ts=NOW,
        updated_ts=NOW,
    )

    baseline = Baseline.from_row(row)

    assert baseline == Baseline(1.5, 0.25, 12, NOW)


def test_alpha_is_the_documented_value() -> None:
    assert ALPHA == 0.1
