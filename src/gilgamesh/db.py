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
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gilgamesh.models import Event, EventType, Severity

SCHEMA_VERSION = 2

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

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_ts    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    sid          TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_ts   REAL NOT NULL,
    last_seen_ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    key    TEXT NOT NULL,
    ts     REAL NOT NULL,
    success INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_key_ts ON login_attempts(key, ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    username   TEXT NOT NULL,
    action     TEXT NOT NULL,
    created_ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(created_ts);

CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ips        TEXT NOT NULL DEFAULT '[]',
    hostname   TEXT,
    vendor     TEXT,
    first_ts   TEXT NOT NULL,
    last_ts    TEXT NOT NULL,
    trusted    INTEGER NOT NULL DEFAULT 0,
    randomised INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_devices_last_ts ON devices(last_ts);
CREATE INDEX IF NOT EXISTS idx_devices_trusted ON devices(trusted);

CREATE TABLE IF NOT EXISTS channels (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,
    config       TEXT NOT NULL,
    min_severity TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    quiet_start  TEXT,
    quiet_end    TEXT
);

-- One row per channel kind: the UI configures Discord, Telegram, and email, once each.
CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_kind ON channels(kind);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
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
            elif int(row["version"]) < SCHEMA_VERSION:
                # Every table is ``CREATE TABLE IF NOT EXISTS``, so bringing an older
                # file up to date *is* running the schema again; recording the new
                # version keeps the marker honest.
                conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))

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

    def insert_audit_entry(
        self, action: str, username: str = "system", created_ts: float = 0.0
    ) -> None:
        """Record that the owner changed something.

        Acknowledging an alert, changing a rule, and adding an allowlist entry all land
        here, so "who turned that off, and when" always has an answer.
        """
        conn = self._connect()
        moment = created_ts or time.time()
        with self._lock:
            conn.execute(
                "INSERT INTO audit_log (ts, username, action, created_ts) VALUES (?, ?, ?, ?)",
                (datetime.fromtimestamp(moment, UTC).isoformat(), username, action, moment),
            )

    def audit_entries(self, limit: int = 100) -> list[sqlite3.Row]:
        """Recent audit entries, newest first."""
        return self.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    # --- generic statements -------------------------------------------------

    def execute(self, sql: str, params: Sequence[object] = ()) -> sqlite3.Cursor:
        """Run one statement and return its cursor.

        Callers read ``lastrowid`` for inserts or ``rowcount`` for updates/deletes.
        All SQL in Gilgamesh is a literal string with bound parameters — never built by
        concatenating user input.
        """
        conn = self._connect()
        with self._lock:
            return conn.execute(sql, tuple(params))

    def query(self, sql: str, params: Sequence[object] = ()) -> list[sqlite3.Row]:
        """Run a query and return all rows."""
        conn = self._connect()
        with self._lock:
            return list(conn.execute(sql, tuple(params)).fetchall())

    def executescript(self, script: str) -> None:
        """Run a multi-statement script such as a schema definition."""
        conn = self._connect()
        with self._lock:
            conn.executescript(script)

    # --- users ---------------------------------------------------------------

    def count_users(self) -> int:
        """Number of accounts. Zero means the install still needs its first-run setup."""
        conn = self._connect()
        with self._lock:
            row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return int(row["n"])

    def create_user(self, username: str, password_hash: str, created_ts: float) -> int:
        """Insert an account and return its id."""
        conn = self._connect()
        with self._lock:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, created_ts) VALUES (?, ?, ?)",
                (username, password_hash, str(created_ts)),
            )
        return int(cursor.lastrowid or 0)

    def get_user(self, username: str) -> tuple[int, str] | None:
        """Return ``(id, password_hash)`` for ``username``, or ``None``."""
        conn = self._connect()
        with self._lock:
            row = conn.execute(
                "SELECT id, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
        return (int(row["id"]), str(row["password_hash"])) if row is not None else None

    # --- sessions ------------------------------------------------------------

    def insert_session(
        self,
        sid: str,
        user_id: int,
        csrf_token: str,
        created_ts: float,
    ) -> None:
        """Store a new session."""
        conn = self._connect()
        with self._lock:
            conn.execute(
                """
                INSERT INTO sessions (sid, user_id, csrf_token, created_ts, last_seen_ts)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sid, user_id, csrf_token, created_ts, created_ts),
            )

    def get_session(self, sid: str) -> tuple[int, str, float, float] | None:
        """Return ``(user_id, csrf_token, created_ts, last_seen_ts)``."""
        conn = self._connect()
        with self._lock:
            row = conn.execute(
                "SELECT user_id, csrf_token, created_ts, last_seen_ts FROM sessions WHERE sid = ?",
                (sid,),
            ).fetchone()
        if row is None:
            return None
        return (
            int(row["user_id"]),
            str(row["csrf_token"]),
            float(row["created_ts"]),
            float(row["last_seen_ts"]),
        )

    def touch_session(self, sid: str, seen_ts: float) -> None:
        """Record activity on a session so the idle timeout slides."""
        conn = self._connect()
        with self._lock:
            conn.execute("UPDATE sessions SET last_seen_ts = ? WHERE sid = ?", (seen_ts, sid))

    def backdate_session(self, sid: str, last_seen_ts: float, created_ts: float) -> None:
        """Move a session's timestamps backwards, to age it out."""
        conn = self._connect()
        with self._lock:
            conn.execute(
                "UPDATE sessions SET last_seen_ts = ?, created_ts = ? WHERE sid = ?",
                (last_seen_ts, created_ts, sid),
            )

    def delete_session(self, sid: str) -> None:
        """Revoke a session immediately."""
        conn = self._connect()
        with self._lock:
            conn.execute("DELETE FROM sessions WHERE sid = ?", (sid,))

    def delete_sessions_for_user(self, user_id: int) -> None:
        """Revoke every session belonging to a user, e.g. after a password change."""
        conn = self._connect()
        with self._lock:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def set_password(self, username: str, password_hash: str) -> None:
        """Replace a user's password hash."""
        conn = self._connect()
        with self._lock:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (password_hash, username),
            )

    def get_username(self, user_id: int) -> str | None:
        """Return the username for a user id."""
        conn = self._connect()
        with self._lock:
            row = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        return str(row["username"]) if row is not None else None

    # --- login throttling ----------------------------------------------------

    def record_login_attempt(self, key: str, ts: float, success: bool) -> None:
        """Record a login outcome for lockout accounting."""
        conn = self._connect()
        with self._lock:
            conn.execute(
                "INSERT INTO login_attempts (key, ts, success) VALUES (?, ?, ?)",
                (key, ts, 1 if success else 0),
            )

    def failed_attempts_since(self, key: str, since: float) -> int:
        """Count failed logins for ``key`` since ``since``."""
        conn = self._connect()
        with self._lock:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM login_attempts "
                "WHERE key = ? AND ts >= ? AND success = 0",
                (key, since),
            ).fetchone()
        return int(row["n"])

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
