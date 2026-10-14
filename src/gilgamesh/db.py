"""SQLite storage.

The database is the single source of truth for configuration, the device
inventory, and every detected event (decision D-005). It runs in **WAL mode** so a
privileged sensor process can write while the unprivileged web process reads.

SQLite is a good fit here: it is in the Python standard library, needs no server,
costs a few megabytes of RAM, and a single file is trivial to back up — all of
which matter on a 4 GB Raspberry Pi.

WAL requires three companions to be safe with several writers: WAL journaling
itself, a ``busy_timeout`` so writers wait instead of raising ``database is
locked``, and short transactions. Short transactions are added as the pipeline
develops (decision: bounded batches), not built speculatively here.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from gilgamesh.models import Event, EventType, Severity

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    ts          TEXT NOT NULL,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    detector    TEXT NOT NULL,
    summary     TEXT NOT NULL,
    src_mac     TEXT,
    src_ip      TEXT,
    dst_mac     TEXT,
    dst_ip      TEXT,
    interface   TEXT,
    details     TEXT NOT NULL,
    incident_id INTEGER,
    dedup_key   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts          ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type_ts     ON events(type, ts);
CREATE INDEX IF NOT EXISTS idx_events_severity_ts ON events(severity, ts);
CREATE INDEX IF NOT EXISTS idx_events_dedup_key   ON events(dedup_key);
"""


class Database:
    """Thread-safe handle to the Gilgamesh SQLite database.

    One connection per process, guarded by a lock. The sensor and the web app are
    separate processes and therefore hold separate connections; WAL mode is what
    makes them safe to use at the same time.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def initialize(self) -> None:
        """Create the database file and schema if they do not exist yet."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        with self._lock:
            conn.executescript(_SCHEMA)
            row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))

    def insert_event(self, event: Event) -> Event:
        """Persist ``event`` and return it unchanged."""
        conn = self._connect()
        with self._lock:
            conn.execute(
                """
                INSERT INTO events (
                    id, ts, type, severity, detector, summary,
                    src_mac, src_ip, dst_mac, dst_ip, interface,
                    details, incident_id, dedup_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.ts.isoformat(),
                    str(event.type),
                    str(event.severity),
                    event.detector,
                    event.summary,
                    event.src_mac,
                    event.src_ip,
                    event.dst_mac,
                    event.dst_ip,
                    event.interface,
                    json.dumps(event.details, separators=(",", ":"), sort_keys=True),
                    event.incident_id,
                    event.dedup_key,
                ),
            )
        return event

    def list_events(self, limit: int = 100) -> list[Event]:
        """Return the most recent events, newest first."""
        conn = self._connect()
        with self._lock:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY ts DESC, rowid DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_event(row) for row in rows]

    def get_event(self, event_id: str) -> Event | None:
        """Return a single event by id, or ``None`` if it does not exist."""
        conn = self._connect()
        with self._lock:
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return _row_to_event(row) if row is not None else None

    def close(self) -> None:
        """Close the connection, checkpointing the WAL."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute("PRAGMA foreign_keys = ON")
            self._conn = conn
        return self._conn


def _row_to_event(row: sqlite3.Row) -> Event:
    """Rebuild an :class:`Event` from a database row."""
    raw_details: Any = row["details"]
    return Event(
        id=row["id"],
        ts=datetime.fromisoformat(row["ts"]),
        type=EventType(row["type"]),
        severity=Severity(row["severity"]),
        detector=row["detector"],
        summary=row["summary"],
        src_mac=row["src_mac"],
        src_ip=row["src_ip"],
        dst_mac=row["dst_mac"],
        dst_ip=row["dst_ip"],
        interface=row["interface"],
        details=json.loads(raw_details),
        incident_id=row["incident_id"],
    )
