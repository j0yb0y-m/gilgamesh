"""Device inventory storage for the web tier.

The inventory *detector* (``gilgamesh.sensors.inventory``) lives in the sensor process and
keeps its devices in memory, because a detector must not depend on the database. The web
process is a different process and cannot see that memory, so the runner mirrors each
observed device into the ``devices`` table and the Devices page reads it back (decision
D-005: the database is the single source of truth for configuration and inventory).

Trust and rename are the only two things the owner can change here. **Trust makes a
device less alarming, never less visible**: the allowlists consult it, but events are
still stored, so "I marked it trusted" can never be used to hide an intrusion.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict

from gilgamesh.db import Database
from gilgamesh.util.net import normalize_mac

#: Reject anything longer than this for a human label. The column is unbounded TEXT;
#: this is a sanity bound so a pasted novel cannot be stored and re-rendered.
_MAX_HOSTNAME = 100


class DeviceRecord(BaseModel):
    """One device as the Devices page needs it."""

    model_config = ConfigDict(frozen=True)

    mac: str
    ips: tuple[str, ...] = ()
    hostname: str | None = None
    vendor: str | None = None
    first_ts: datetime
    last_ts: datetime
    trusted: bool = False
    randomised: bool = False


def _normalize_ip(value: str) -> str:
    """Return ``value`` as a canonical IPv6/IPv4 string, or raise ``ValueError``."""
    return str(ipaddress.ip_address(value.strip()))


class DeviceStore:
    """Read and update the persisted device inventory."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def list(self) -> list[DeviceRecord]:
        """Every known device, most recently seen first."""
        rows = self._db.query("SELECT * FROM devices ORDER BY last_ts DESC, mac ASC")
        return [_row_to_device(row) for row in rows]

    def get(self, mac: str) -> DeviceRecord | None:
        """One device by MAC, or ``None``."""
        row = self._db.query("SELECT * FROM devices WHERE mac = ?", (normalize_mac(mac),))
        return _row_to_device(row[0]) if row else None

    def upsert(
        self,
        mac: str,
        *,
        ip: str | None = None,
        hostname: str | None = None,
        vendor: str | None = None,
        randomised: bool = False,
        seen_ts: datetime | None = None,
    ) -> DeviceRecord:
        """Record a sighting, creating the row on first contact.

        The first-seen time is written once and never moves; a repeat sighting only
        extends ``last_ts`` and merges the new address, so the page shows a true
        history rather than whatever the most recent packet happened to carry.
        """
        key = normalize_mac(mac)
        moment = seen_ts or datetime.now(UTC)
        existing = self.get(key)
        addresses: set[str] = set(existing.ips) if existing else set()
        if ip is not None:
            addresses.add(_normalize_ip(ip))

        first = existing.first_ts if existing else moment
        trusted = existing.trusted if existing else False
        stored_hostname = existing.hostname if existing else None
        # A detector-supplied hostname fills a blank label but never overwrites one the
        # owner set by hand.
        if stored_hostname is None and hostname:
            stored_hostname = hostname[:_MAX_HOSTNAME]

        self._db.execute(
            """
            INSERT INTO devices (mac, ips, hostname, vendor, first_ts, last_ts, trusted, randomised)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ips        = excluded.ips,
                hostname   = excluded.hostname,
                vendor     = excluded.vendor,
                last_ts    = excluded.last_ts,
                randomised = excluded.randomised
            """,
            (
                key,
                json.dumps(sorted(addresses), separators=(",", ":")),
                stored_hostname,
                vendor or (existing.vendor if existing else None),
                first.isoformat(),
                moment.isoformat(),
                1 if trusted else 0,
                1 if randomised else 0,
            ),
        )
        return DeviceRecord(
            mac=key,
            ips=tuple(sorted(addresses)),
            hostname=stored_hostname,
            vendor=vendor or (existing.vendor if existing else None),
            first_ts=first,
            last_ts=moment,
            trusted=trusted,
            randomised=randomised,
        )

    def set_trusted(self, mac: str, trusted: bool) -> None:
        """Mark a device trusted (or not). Unknown devices are refused."""
        key = normalize_mac(mac)
        cursor = self._db.execute(
            "UPDATE devices SET trusted = ? WHERE mac = ?", (1 if trusted else 0, key)
        )
        if cursor.rowcount == 0:
            raise KeyError(mac)

    def rename(self, mac: str, hostname: str) -> None:
        """Give a device a human label. A blank label clears it. Unknown devices refuse."""
        key = normalize_mac(mac)
        label = hostname.strip()[:_MAX_HOSTNAME] or None
        cursor = self._db.execute("UPDATE devices SET hostname = ? WHERE mac = ?", (label, key))
        if cursor.rowcount == 0:
            raise KeyError(mac)


def _row_to_device(row: sqlite3.Row) -> DeviceRecord:
    """Rebuild a :class:`DeviceRecord` from a database row."""
    return DeviceRecord(
        mac=row["mac"],
        ips=tuple(json.loads(row["ips"])),
        hostname=row["hostname"],
        vendor=row["vendor"],
        first_ts=datetime.fromisoformat(row["first_ts"]),
        last_ts=datetime.fromisoformat(row["last_ts"]),
        trusted=bool(row["trusted"]),
        randomised=bool(row["randomised"]),
    )


__all__ = ["DeviceRecord", "DeviceStore"]
