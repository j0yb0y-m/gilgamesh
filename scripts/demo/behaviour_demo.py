"""Replay the committed behaviour fixtures through the production engine.

This is a developer demo, not a second detector. It seeds a throwaway database,
replays ``normal.eve.jsonl`` to build baselines, then replays
``attack.eve.jsonl`` and prints the events the real aggregator produced. Nothing
touches the running services, the host network, or ``/var/lib/gilgamesh``.

Usage::

    uv run python scripts/demo/behaviour_demo.py \
        --fixtures tests/fixtures/behaviour \
        --data-dir /tmp/gilgamesh-demo

``calibration_days=0`` is the documented lab/demo mode; the 20-sample gate is
still enforced, so the demo cannot bypass the production calibration rule.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from gilgamesh.behaviour.aggregate import BehaviourAggregator
from gilgamesh.behaviour.attribution import DeviceMap
from gilgamesh.behaviour.eve import DnsFact, FlowFact, parse_behaviour_record
from gilgamesh.behaviour.store import BehaviourStore
from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event

#: EVE flow records carry IPs, not MACs. These are the same synthetic inventory
#: pairs the acceptance test uses, so a replayed fixture is attributable.
DEMO_DEVICES: tuple[tuple[str, str, str], ...] = (
    ("aa:bb:cc:00:00:01", "10.0.0.10", "Camera"),
    ("aa:bb:cc:00:00:02", "10.0.0.11", "Phone"),
    ("aa:bb:cc:00:00:03", "10.0.0.12", "Laptop"),
    ("aa:bb:cc:00:00:04", "10.0.0.13", "TV"),
    ("aa:bb:cc:00:00:05", "10.0.0.14", "Thermostat"),
)

FIXTURE_START = datetime(2026, 11, 1, tzinfo=UTC)
_BUCKET = timedelta(minutes=15)


def run_demo(
    fixtures_dir: Path,
    data_dir: Path,
    *,
    calibration_days: int = 0,
    force: bool = False,
) -> list[Event]:
    """Replay the fixtures and return every behaviour event produced."""
    target = _allowed_data_dir(data_dir, force=force)
    target.mkdir(parents=True, exist_ok=True)
    database = Database(target / "gilgamesh.db")
    database.initialize()
    try:
        _seed_devices(database)
        store = BehaviourStore(database)
        devices = DeviceMap()
        devices.refresh(DeviceStore(database).list())
        clock = [FIXTURE_START]
        aggregator = BehaviourAggregator(
            store,
            devices,
            calibration_days=calibration_days,
            grace_seconds=0,
            clock=lambda: clock[0],
        )
        events = _replay(aggregator, fixtures_dir / "normal.eve.jsonl", clock)
        events.extend(_replay(aggregator, fixtures_dir / "attack.eve.jsonl", clock))
        events.extend(aggregator.close())
        for event in events:
            database.insert_event(event)
        return events
    finally:
        database.close()


def _replay(
    aggregator: BehaviourAggregator,
    path: Path,
    clock: list[datetime],
) -> list[Event]:
    """Feed one JSONL file in bucket order, flushing each bucket at its end."""
    events: list[Event] = []
    bucket: datetime | None = None
    for record in _load(path):
        fact = parse_behaviour_record(record)
        if not isinstance(fact, FlowFact | DnsFact):
            continue
        start = _floor(fact.ts)
        if bucket is not None and start > bucket:
            clock[0] = bucket + _BUCKET
            events.extend(aggregator.flush(now=clock[0]))
        bucket = start
        aggregator.record(fact)
    if bucket is not None:
        clock[0] = bucket + _BUCKET
        events.extend(aggregator.flush(now=clock[0]))
    return events


def _load(path: Path) -> list[dict[str, object]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [cast("dict[str, object]", json.loads(line)) for line in lines if line.strip()]


def _floor(moment: datetime) -> datetime:
    epoch = int(moment.timestamp())
    return datetime.fromtimestamp(epoch - epoch % 900, UTC)


def _seed_devices(database: Database) -> None:
    store = DeviceStore(database)
    for mac, ip, label in DEMO_DEVICES:
        store.upsert(mac, ip=ip, hostname=label, seen_ts=FIXTURE_START)


def _allowed_data_dir(data_dir: Path, *, force: bool) -> Path:
    """Only /tmp and this workspace are safe defaults for a throwaway demo DB."""
    target = data_dir.expanduser().resolve()
    if force:
        return target
    workspace = Path(__file__).resolve().parents[2]
    temp_root = Path(tempfile.gettempdir()).resolve()
    if target.is_relative_to(temp_root) or target.is_relative_to(workspace):
        return target
    raise ValueError(f"refusing to write to {target}; use /tmp or the workspace, or pass --force")


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the CLI, run the demo, and print the event table."""
    workspace = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Replay the behaviour fixtures offline.")
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=workspace / "tests" / "fixtures" / "behaviour",
    )
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--calibration-days", type=int, default=0)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        events = run_demo(
            args.fixtures,
            args.data_dir,
            calibration_days=args.calibration_days,
            force=args.force,
        )
    except ValueError as exc:
        parser.error(str(exc))

    print(f"{len(events)} behaviour event(s) in {args.data_dir}")
    print(f"{'time':<20} {'detector':<28} {'severity':<8} summary")
    for event in events:
        print(
            f"{event.ts.isoformat(timespec='seconds'):<20} "
            f"{event.detector:<28} {event.severity:<8} {event.summary}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
