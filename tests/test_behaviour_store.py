"""Schema 4 behaviour tables and the SQL behind them.

The behaviour engine writes 15-minute buckets, per-device baselines, and a bounded
set of seen destinations. This module pins the properties the rest of the engine
relies on: absolute versus additive upserts, ordered reads, first-seen preservation,
the per-device destination bound, and a status row that survives a restart.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gilgamesh.behaviour.store import (
    ActivityBucket,
    BaselineRow,
    BehaviourStatus,
    BehaviourStore,
)
from gilgamesh.db import Database

BUCKET = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
MAC = "aa:bb:cc:dd:ee:01"


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def store(database: Database) -> BehaviourStore:
    return BehaviourStore(database)


def test_initialize_creates_behaviour_tables_and_schema_version_4(database: Database) -> None:
    names = {
        row["name"] for row in database.query("SELECT name FROM sqlite_master WHERE type='table'")
    }

    assert {
        "device_activity",
        "device_baselines",
        "device_destinations",
        "ai_explanations",
    } <= names
    assert database.query("SELECT version FROM schema_version")[0]["version"] == 4


def test_bucket_upsert_is_absolute_unless_additive(store: BehaviourStore) -> None:
    bucket = ActivityBucket(MAC, BUCKET, bytes_out=100)

    store.write_bucket(bucket)
    store.write_bucket(replace(bucket, bytes_out=150))
    assert store.buckets(MAC, since=BUCKET)[0].bytes_out == 150

    store.write_bucket(replace(bucket, bytes_out=10), additive=True)
    assert store.buckets(MAC, since=BUCKET)[0].bytes_out == 160


def test_bucket_values_round_trip(store: BehaviourStore) -> None:
    bucket = ActivityBucket(
        MAC,
        BUCKET,
        bytes_in=1200,
        bytes_out=4000,
        packets_in=8,
        packets_out=10,
        flows=2,
        unique_dst=3,
        dns_queries=4,
        dns_unique_names=5,
    )

    store.write_bucket(bucket)

    assert store.buckets(MAC, since=BUCKET) == [bucket]


def test_buckets_are_filtered_and_ordered(store: BehaviourStore) -> None:
    later = BUCKET.replace(minute=15)
    store.write_bucket(ActivityBucket(MAC, later, flows=2))
    store.write_bucket(ActivityBucket(MAC, BUCKET, flows=1))
    store.write_bucket(ActivityBucket("aa:bb:cc:dd:ee:02", BUCKET, flows=9))

    assert [b.bucket_ts for b in store.buckets(MAC, since=BUCKET)] == [BUCKET, later]
    assert [b.flows for b in store.buckets(MAC, since=later)] == [2]
    assert store.buckets("aa:bb:cc:dd:ee:03", since=BUCKET) == []


@pytest.mark.parametrize(
    "field",
    [
        "bytes_in",
        "bytes_out",
        "packets_in",
        "packets_out",
        "flows",
        "unique_dst",
        "dns_queries",
        "dns_unique_names",
    ],
)
def test_negative_bucket_values_are_rejected(field: str) -> None:
    with pytest.raises(ValueError):
        ActivityBucket(MAC, BUCKET, **{field: -1})  # type: ignore[arg-type]


def test_baseline_round_trip_and_upsert(store: BehaviourStore) -> None:
    first = BaselineRow(
        device_mac=MAC,
        metric="bytes_out_log",
        mean=1.5,
        variance=0.25,
        samples=12,
        learning_started_ts=BUCKET,
        updated_ts=BUCKET,
    )
    second = replace(first, metric="unique_dst", mean=4.0, variance=1.0)

    store.upsert_baseline(first)
    store.upsert_baseline(second)
    store.upsert_baseline(
        replace(first, mean=2.0, samples=13, updated_ts=BUCKET.replace(minute=15))
    )

    rows = {row.metric: row for row in store.load_baselines()}
    assert rows == {
        "bytes_out_log": replace(first, mean=2.0, samples=13, updated_ts=BUCKET.replace(minute=15)),
        "unique_dst": second,
    }


def test_status_defaults_when_missing(store: BehaviourStore) -> None:
    status = store.read_status()

    assert status.enabled is True
    assert status.suricata_available is False
    assert status.flows_seen == 0
    assert status.updated_ts is None


def test_status_round_trip(store: BehaviourStore) -> None:
    status = BehaviourStatus(
        updated_ts=BUCKET,
        last_flow_ts=BUCKET,
        last_dns_ts=BUCKET.replace(minute=5),
        flows_seen=7,
        dns_seen=3,
        parse_errors=1,
        unknown_ip_flows=2,
        ipv6_flows=4,
        devices_tracked=5,
        devices_dropped=6,
        late_buckets=1,
        last_flush_ts=BUCKET.replace(minute=15),
        enabled=False,
        suricata_available=True,
    )

    store.write_status(status)

    assert store.read_status() == status


def test_status_unreadable_value_returns_defaults(
    database: Database, store: BehaviourStore
) -> None:
    database.set_setting("behaviour_status", "{not json")

    assert store.read_status() == BehaviourStatus()


def test_seen_destinations_returns_only_known_ips(store: BehaviourStore) -> None:
    store.record_destinations(MAC, ["93.184.216.34", "1.1.1.1"], seen_ts=BUCKET)

    assert store.seen_destinations(MAC, ["93.184.216.34", "8.8.8.8"]) == {"93.184.216.34"}
    assert store.seen_destinations("aa:bb:cc:dd:ee:02", ["93.184.216.34"]) == set()
    assert store.seen_destinations(MAC, []) == set()


def test_destinations_keep_first_seen_and_update_last_seen(
    database: Database, store: BehaviourStore
) -> None:
    later = BUCKET.replace(minute=15)
    store.record_destinations(MAC, ["93.184.216.34"], seen_ts=BUCKET)
    store.record_destinations(MAC, ["93.184.216.34"], seen_ts=later)

    rows = database.query("SELECT * FROM device_destinations")
    assert len(rows) == 1
    assert rows[0]["first_seen_ts"] == BUCKET.isoformat()
    assert rows[0]["last_seen_ts"] == later.isoformat()


def test_destinations_are_bounded_per_device(store: BehaviourStore) -> None:
    store.record_destinations(MAC, ["1.1.1.1"], seen_ts=BUCKET)
    store.record_destinations(MAC, ["8.8.8.8"], seen_ts=BUCKET.replace(minute=5))
    store.record_destinations(MAC, ["9.9.9.9"], seen_ts=BUCKET.replace(minute=10))
    store.record_destinations("aa:bb:cc:dd:ee:02", ["1.1.1.1"], seen_ts=BUCKET)

    store.record_destinations(MAC, ["1.1.1.1"], seen_ts=BUCKET.replace(minute=15), max_per_device=2)

    assert store.seen_destinations(MAC, ["1.1.1.1", "8.8.8.8", "9.9.9.9"]) == {"1.1.1.1", "9.9.9.9"}
    assert store.seen_destinations("aa:bb:cc:dd:ee:02", ["1.1.1.1"]) == {"1.1.1.1"}


def test_destination_ips_are_normalized_and_deduplicated(
    database: Database, store: BehaviourStore
) -> None:
    store.record_destinations(MAC, ["2001:0db8::1", "2001:db8::1"], seen_ts=BUCKET)

    assert store.seen_destinations(MAC, ["2001:db8::1"]) == {"2001:db8::1"}
    assert database.query("SELECT COUNT(*) AS n FROM device_destinations")[0]["n"] == 1


def test_ai_explanations_keep_failed_rows_and_lookup_the_latest_ok(database: Database) -> None:
    insert = (
        "INSERT INTO ai_explanations "
        "(event_id, provider, model, prompt_version, status, text, latency_ms, "
        "prompt_tokens, completion_tokens, created_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    key = ("evt-1", "openai", "gpt-test", "behaviour-ai-v1")
    database.execute(insert, (*key, "ok", "first", 100, 10, 20, BUCKET.isoformat()))
    database.execute(insert, (*key, "error", "", 50, 0, 0, BUCKET.isoformat()))
    database.execute(insert, (*key, "ok", "second", 120, 11, 21, BUCKET.isoformat()))

    rows = database.query(
        "SELECT text FROM ai_explanations "
        "WHERE event_id = ? AND provider = ? AND model = ? "
        "AND prompt_version = ? AND status = 'ok' "
        "ORDER BY id DESC LIMIT 1",
        key,
    )

    assert [row["text"] for row in rows] == ["second"]
    assert database.query("SELECT COUNT(*) AS n FROM ai_explanations")[0]["n"] == 3


def test_existing_schema_three_database_upgrades_in_place(tmp_path: Path) -> None:
    path = tmp_path / "gilgamesh.db"
    legacy = sqlite3.connect(path)
    legacy.executescript(
        "CREATE TABLE schema_version (version INTEGER NOT NULL);"
        "INSERT INTO schema_version (version) VALUES (3);"
    )
    legacy.close()

    db = Database(path)
    db.initialize()

    assert db.query("SELECT version FROM schema_version")[0]["version"] == 4
    assert db.query("SELECT COUNT(*) AS n FROM device_activity")[0]["n"] == 0
    db.close()
