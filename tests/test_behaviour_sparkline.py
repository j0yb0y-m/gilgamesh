"""The device-detail sparkline is plain SVG built on the server.

No chart library, no JavaScript: the template only needs two ready-made point
strings and the maximum value for the axis. These tests pin the geometry so the
line always stays inside its viewBox, including the degenerate cases of no data
and a single bucket.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from gilgamesh.behaviour.sparkline import build_sparkline
from gilgamesh.behaviour.store import ActivityBucket

MAC = "aa:bb:cc:dd:ee:01"
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


def bucket(*, minutes: int, out: int = 0, incoming: int = 0) -> ActivityBucket:
    return ActivityBucket(
        MAC,
        NOW - timedelta(minutes=minutes),
        bytes_out=out,
        bytes_in=incoming,
    )


def _points(value: str) -> list[tuple[float, float]]:
    points: list[tuple[float, float]] = []
    for point in value.split():
        x, y = point.split(",")
        points.append((float(x), float(y)))
    return points


def test_sparkline_points_stay_inside_the_viewbox() -> None:
    buckets = [bucket(minutes=30, out=1000), bucket(minutes=15, out=3000)]

    spark = build_sparkline(buckets, width=600, height=80)

    points = _points(spark.out_points)
    assert len(points) == len(buckets)
    assert all(0 <= x <= 600 and 0 <= y <= 80 for x, y in points)
    assert spark.max_bytes == 3000


def test_sparkline_empty_buckets_produce_empty_lines() -> None:
    spark = build_sparkline([], width=600, height=80)

    assert spark.out_points == ""
    assert spark.in_points == ""
    assert spark.max_bytes == 0
    assert (spark.width, spark.height) == (600, 80)


def test_sparkline_single_bucket_does_not_divide_by_zero() -> None:
    spark = build_sparkline([bucket(minutes=5, out=42)], width=600, height=80)

    assert len(_points(spark.out_points)) == 1
    assert spark.max_bytes == 42


def test_sparkline_x_is_monotonic_and_uses_both_series() -> None:
    buckets = [
        bucket(minutes=45, out=100, incoming=50),
        bucket(minutes=30, out=200, incoming=400),
        bucket(minutes=15, out=50, incoming=25),
    ]

    spark = build_sparkline(buckets, width=600, height=80)

    xs = [x for x, _ in _points(spark.out_points)]
    assert xs == sorted(xs)
    assert len(_points(spark.in_points)) == len(buckets)
    assert spark.max_bytes == 400
