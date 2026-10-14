"""M13 — device inventory storage (the Devices page's data source).

The inventory detector (M7) is in-memory in the sensor process, so the web tier needs a
persisted copy to render. These tests pin the properties the page relies on: the first
sighting time never moves, repeat sightings extend ``last_seen`` and accumulate
addresses, a rounded MAC is stored canonically, and trust/rename are explicit actions.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore


@pytest.fixture
def store(tmp_path: Path) -> Iterator[DeviceStore]:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    yield DeviceStore(database)
    database.close()


def test_first_sighting_records_both_timestamps(store: DeviceStore) -> None:
    when = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)

    device = store.upsert("AA:BB:CC:00:00:01", ip="10.0.0.5", seen_ts=when)

    assert device.mac == "aa:bb:cc:00:00:01"
    assert device.ips == ("10.0.0.5",)
    assert device.first_ts == when
    assert device.last_ts == when
    assert device.trusted is False


def test_repeat_sighting_keeps_first_seen_and_adds_addresses(store: DeviceStore) -> None:
    first = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
    later = datetime(2026, 10, 14, 13, 0, tzinfo=UTC)
    store.upsert("aa:bb:cc:00:00:01", ip="10.0.0.5", seen_ts=first)

    device = store.upsert("aa:bb:cc:00:00:01", ip="10.0.0.6", seen_ts=later)

    assert device.first_ts == first
    assert device.last_ts == later
    assert device.ips == ("10.0.0.5", "10.0.0.6")


def test_list_is_newest_first(store: DeviceStore) -> None:
    store.upsert("00:00:00:00:00:01", seen_ts=datetime(2026, 10, 14, 10, 0, tzinfo=UTC))
    store.upsert("00:00:00:00:00:02", seen_ts=datetime(2026, 10, 14, 11, 0, tzinfo=UTC))

    macs = [device.mac for device in store.list()]

    assert macs == ["00:00:00:00:00:02", "00:00:00:00:00:01"]


def test_trust_toggles(store: DeviceStore) -> None:
    store.upsert("00:00:00:00:00:01")

    store.set_trusted("00:00:00:00:00:01", True)
    assert store.get("00:00:00:00:00:01").trusted is True  # type: ignore[union-attr]

    store.set_trusted("00:00:00:00:00:01", False)
    assert store.get("00:00:00:00:00:01").trusted is False  # type: ignore[union-attr]


def test_rename_sets_and_clears_the_hostname(store: DeviceStore) -> None:
    store.upsert("00:00:00:00:00:01")

    store.rename("00:00:00:00:00:01", "Living-room TV")
    assert store.get("00:00:00:00:00:01").hostname == "Living-room TV"  # type: ignore[union-attr]

    store.rename("00:00:00:00:00:01", "   ")
    assert store.get("00:00:00:00:00:01").hostname is None  # type: ignore[union-attr]


def test_randomised_flag_is_remembered(store: DeviceStore) -> None:
    device = store.upsert("02:00:00:00:00:01", randomised=True)

    assert device.randomised is True


def test_malformed_mac_is_refused(store: DeviceStore) -> None:
    with pytest.raises(ValueError):
        store.upsert("not-a-mac")


def test_unknown_device_is_refused(store: DeviceStore) -> None:
    with pytest.raises(KeyError):
        store.set_trusted("00:00:00:00:00:09", True)
    with pytest.raises(KeyError):
        store.rename("00:00:00:00:00:09", "x")


def test_survives_reopening_the_database(tmp_path: Path) -> None:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    DeviceStore(database).upsert("00:00:00:00:00:01", hostname="Laptop")
    database.close()

    reopened = Database(tmp_path / "gilgamesh.db")
    reopened.initialize()
    assert DeviceStore(reopened).get("00:00:00:00:00:01").hostname == "Laptop"  # type: ignore[union-attr]
    reopened.close()
