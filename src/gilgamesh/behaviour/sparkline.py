"""Server-rendered SVG geometry for the device-detail sparkline.

The browser never needs a chart library: this module turns the last 24 hours of
15-minute buckets into two ``polyline`` point strings. Coordinates are scaled
against the larger of the two byte series so the two lines stay comparable.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from gilgamesh.behaviour.store import ActivityBucket


@dataclass(frozen=True, slots=True)
class Sparkline:
    """Ready-to-render sparkline geometry for one device."""

    width: int
    height: int
    out_points: str
    in_points: str
    max_bytes: int


def build_sparkline(
    buckets: Sequence[ActivityBucket], *, width: int = 600, height: int = 80
) -> Sparkline:
    """Turn traffic buckets into SVG point strings.

    The x axis is the bucket's position in the sequence (not its timestamp), so a
    quiet period without stored buckets compresses rather than leaving a gap. The
    y axis is inverted because SVG's origin is the top-left corner.
    """
    if not buckets:
        return Sparkline(width=width, height=height, out_points="", in_points="", max_bytes=0)

    max_bytes = max(max(bucket.bytes_in, bucket.bytes_out) for bucket in buckets)
    step = width / max(len(buckets) - 1, 1)
    out_points = " ".join(
        _point(index * step, bucket.bytes_out, max_bytes=max_bytes, height=height)
        for index, bucket in enumerate(buckets)
    )
    in_points = " ".join(
        _point(index * step, bucket.bytes_in, max_bytes=max_bytes, height=height)
        for index, bucket in enumerate(buckets)
    )
    return Sparkline(
        width=width,
        height=height,
        out_points=out_points,
        in_points=in_points,
        max_bytes=max_bytes,
    )


def _point(x: float, value: int, *, max_bytes: int, height: int) -> str:
    y = height - (value / max_bytes) * height if max_bytes else float(height)
    return f"{x:.1f},{y:.1f}"


__all__ = ["Sparkline", "build_sparkline"]
