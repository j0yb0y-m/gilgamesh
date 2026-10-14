"""Notification channel storage (M13, Notifications page).

The notifier classes (``gilgamesh.notifiers``) know how to *send*; this module owns what
the owner has *configured*, and it exists because of one rule: **a secret is written but
never read back**. Discord's webhook URL and Telegram's bot token are themselves bearer
credentials, and an SMTP password obviously is, so:

* the form submits a blank field to mean "leave the stored secret alone" — the page has
  no way to echo it, so it must not be possible to accidentally clear it by saving;
* only the fields that belong to a channel's kind are stored on its row, so a Discord row
  can never be carrying a stale SMTP password;
* every value is validated here, before it reaches the database, and nothing is ever
  interpolated into a shell or a generated config file (constraint: no shell from input).
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from gilgamesh.db import Database
from gilgamesh.models import Severity
from gilgamesh.notifiers.base import (
    ChannelConfig,
    ChannelKind,
    NotificationChannel,
    Transport,
)
from gilgamesh.notifiers.discord import DiscordChannel
from gilgamesh.notifiers.email import EmailChannel
from gilgamesh.notifiers.telegram import TelegramChannel

_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

#: The fields each kind understands. Anything else in a submitted form is ignored, so a
#: crafted POST cannot inject an unexpected key into the stored JSON.
_KIND_FIELDS: dict[ChannelKind, tuple[str, ...]] = {
    ChannelKind.DISCORD: ("webhook_url",),
    ChannelKind.TELEGRAM: ("bot_token", "chat_id"),
    ChannelKind.EMAIL: (
        "smtp_host",
        "smtp_port",
        "smtp_username",
        "smtp_password",
        "smtp_use_tls",
        "smtp_start_tls",
        "sender",
        "recipients",
    ),
}

#: Fields that must never be echoed to the browser and whose blank value means "unchanged".
_SECRET_FIELDS: dict[ChannelKind, tuple[str, ...]] = {
    ChannelKind.DISCORD: ("webhook_url",),
    ChannelKind.TELEGRAM: ("bot_token",),
    ChannelKind.EMAIL: ("smtp_password",),
}

#: Fields that are only meaningful when present, per kind, for the "configured?" check.
_REQUIRED_FIELDS: dict[ChannelKind, tuple[str, ...]] = {
    ChannelKind.DISCORD: ("webhook_url",),
    ChannelKind.TELEGRAM: ("bot_token", "chat_id"),
    ChannelKind.EMAIL: ("smtp_host", "sender", "recipients"),
}

_INT_FIELDS = frozenset({"smtp_port"})
_BOOL_FIELDS = frozenset({"smtp_use_tls", "smtp_start_tls"})
_LIST_FIELDS = frozenset({"recipients"})


class ChannelConfigError(ValueError):
    """A submitted channel value was not acceptable. The message is safe to show."""


class ChannelRecord(BaseModel):
    """One stored channel, exactly as the database holds it."""

    model_config = ConfigDict(frozen=True)

    id: int
    kind: ChannelKind
    enabled: bool
    min_severity: Severity
    quiet_start: str | None = None
    quiet_end: str | None = None
    #: Kind-specific settings. Secret values live here too — callers must not render
    #: them; use :meth:`ChannelStore.is_secret_set` for a boolean instead.
    config: dict[str, Any] = {}


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_quiet(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if not _HHMM.match(value):
        raise ChannelConfigError("quiet hours must look like HH:MM (24-hour)")
    return value


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ChannelConfigError("SMTP port must be a whole number") from exc
    if not 1 <= port <= 65535:
        raise ChannelConfigError("SMTP port must be between 1 and 65535")
    return port


def _parse_severity(value: str | Severity) -> Severity:
    try:
        return Severity(str(value))
    except ValueError as exc:
        allowed = ", ".join(level.value for level in Severity)
        raise ChannelConfigError(f"minimum severity must be one of: {allowed}") from exc


def _coerce_field(name: str, raw: str) -> object:
    if name in _INT_FIELDS:
        return _parse_port(raw)
    if name in _BOOL_FIELDS:
        return _parse_bool(raw)
    if name in _LIST_FIELDS:
        return [item.strip() for item in re.split(r"[,\s]+", raw.strip()) if item.strip()]
    return raw.strip()


class ChannelStore:
    """Read and update the configured alert channels."""

    def __init__(self, database: Database) -> None:
        self._db = database

    # --- reading -------------------------------------------------------------

    def list(self) -> list[ChannelRecord]:
        """Every configured channel, oldest first."""
        rows = self._db.query("SELECT * FROM channels ORDER BY id ASC")
        return [_row_to_record(row) for row in rows]

    def get(self, kind: ChannelKind) -> ChannelRecord | None:
        """The channel of ``kind``, or ``None`` if it has never been saved."""
        rows = self._db.query("SELECT * FROM channels WHERE kind = ?", (str(kind),))
        return _row_to_record(rows[0]) if rows else None

    def get_by_id(self, channel_id: int) -> ChannelRecord | None:
        """The channel with the given row id, or ``None``."""
        rows = self._db.query("SELECT * FROM channels WHERE id = ?", (channel_id,))
        return _row_to_record(rows[0]) if rows else None

    # --- writing -------------------------------------------------------------

    def save(
        self,
        kind: ChannelKind,
        *,
        fields: Mapping[str, str],
        enabled: bool = True,
        min_severity: str | Severity = Severity.MEDIUM,
        quiet_start: str | None = None,
        quiet_end: str | None = None,
    ) -> ChannelRecord:
        """Create or replace the channel of ``kind``.

        Blank secret fields keep whatever was stored before, because the UI has no way
        to show the current value and re-entering it should not be required.
        """
        severity = _parse_severity(min_severity)
        begins, finishes = _parse_quiet(quiet_start or ""), _parse_quiet(quiet_end or "")
        if (begins is None) != (finishes is None):
            raise ChannelConfigError("set both quiet-hour ends, or neither")

        existing = self.get(kind)
        merged: dict[str, Any] = dict(existing.config) if existing else {}
        for name in _KIND_FIELDS[kind]:
            if name not in fields:
                continue
            raw = fields[name]
            if name in _SECRET_FIELDS[kind] and not raw.strip():
                continue  # blank secret keeps the stored value
            merged[name] = _coerce_field(name, raw)

        self._db.execute(
            """
            INSERT INTO channels (kind, config, min_severity, enabled, quiet_start, quiet_end)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(kind) DO UPDATE SET
                config       = excluded.config,
                min_severity = excluded.min_severity,
                enabled      = excluded.enabled,
                quiet_start  = excluded.quiet_start,
                quiet_end    = excluded.quiet_end
            """,
            (
                str(kind),
                json.dumps(merged, separators=(",", ":"), sort_keys=True),
                str(severity),
                1 if enabled else 0,
                begins,
                finishes,
            ),
        )
        record = self.get(kind)
        if record is None:  # pragma: no cover - the row was just written
            raise ChannelConfigError("channel could not be saved")
        return record

    def delete(self, kind: ChannelKind) -> None:
        """Forget a channel entirely, including its secrets."""
        self._db.execute("DELETE FROM channels WHERE kind = ?", (str(kind),))

    # --- building live channels ---------------------------------------------

    def to_channel_config(self, record: ChannelRecord) -> ChannelConfig:
        """Turn a stored row back into the :class:`ChannelConfig` the notifiers use."""
        data = record.config
        recipients = data.get("recipients") or ()
        return ChannelConfig(
            enabled=record.enabled,
            min_severity=record.min_severity,
            quiet_start=record.quiet_start,
            quiet_end=record.quiet_end,
            webhook_url=data.get("webhook_url") or None,
            bot_token=data.get("bot_token") or None,
            chat_id=data.get("chat_id") or None,
            smtp_host=data.get("smtp_host") or None,
            smtp_port=int(data.get("smtp_port") or 587),
            smtp_username=data.get("smtp_username") or None,
            smtp_password=data.get("smtp_password") or None,
            smtp_use_tls=bool(data.get("smtp_use_tls", True)),
            smtp_start_tls=bool(data.get("smtp_start_tls", True)),
            sender=data.get("sender") or None,
            recipients=tuple(recipients),
        )

    def build_channel(
        self, record: ChannelRecord, *, transport: Transport | None = None
    ) -> NotificationChannel:
        """Construct the live notifier for a stored channel."""
        config = self.to_channel_config(record)
        classes: dict[ChannelKind, type[NotificationChannel]] = {
            ChannelKind.DISCORD: DiscordChannel,
            ChannelKind.TELEGRAM: TelegramChannel,
            ChannelKind.EMAIL: EmailChannel,
        }
        return classes[record.kind](config, transport=transport)

    # --- small static helpers the templates use -----------------------------

    @staticmethod
    def secret_fields(kind: ChannelKind) -> tuple[str, ...]:
        """The names of the fields that carry a secret for ``kind``."""
        return _SECRET_FIELDS[kind]

    @staticmethod
    def is_secret_set(record: ChannelRecord, field: str) -> bool:
        """Whether a secret field currently holds a value, without revealing it."""
        return bool(record.config.get(field))

    @staticmethod
    def is_configured(kind: ChannelKind, config: Mapping[str, Any]) -> bool:
        """Whether the fields required to deliver on ``kind`` are all present."""
        return all(config.get(name) for name in _REQUIRED_FIELDS[kind])


def _row_to_record(row: sqlite3.Row) -> ChannelRecord:
    """Rebuild a :class:`ChannelRecord` from a database row."""
    return ChannelRecord(
        id=int(row["id"]),
        kind=ChannelKind(row["kind"]),
        enabled=bool(row["enabled"]),
        min_severity=Severity(row["min_severity"]),
        quiet_start=row["quiet_start"],
        quiet_end=row["quiet_end"],
        config=json.loads(row["config"]),
    )


__all__ = ["ChannelConfigError", "ChannelRecord", "ChannelStore"]
