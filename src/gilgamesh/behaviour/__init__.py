"""Local, per-device behavioural analytics for Gilgamesh.

The package reads Suricata's ``flow`` and ``dns`` records, attributes them to the
device inventory, aggregates them into 15-minute buckets, and scores them against
per-device baselines. It never blocks traffic and never calls an external service.
"""

from __future__ import annotations

__all__: list[str] = []
