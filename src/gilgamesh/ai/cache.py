"""Persistence for AI explanation results.

A row is one attempt: ``status='ok'`` rows are cache hits, ``status='error'``
rows are audit breadcrumbs and are never returned. The lookup is keyed by event,
provider, model, and prompt version, so changing any of them starts fresh.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, replace
from datetime import datetime

from gilgamesh.db import Database


@dataclass(frozen=True, slots=True)
class ExplanationRow:
    """One explanation attempt, successful or failed."""

    id: int | None
    event_id: str
    provider: str
    model: str
    prompt_version: str
    status: str
    text: str
    latency_ms: int | None
    prompt_tokens: int | None
    completion_tokens: int | None
    created_ts: datetime


class ExplanationCache:
    """Read and write the ``ai_explanations`` table."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def get(
        self, event_id: str, provider: str, model: str, prompt_version: str
    ) -> ExplanationRow | None:
        """The latest successful explanation for this exact key, or ``None``."""
        rows = self._db.query(
            """
            SELECT * FROM ai_explanations
            WHERE event_id = ? AND provider = ? AND model = ?
              AND prompt_version = ? AND status = 'ok'
            ORDER BY id DESC LIMIT 1
            """,
            (event_id, provider, model, prompt_version),
        )
        return _row_to_explanation(rows[0]) if rows else None

    def put(self, row: ExplanationRow) -> ExplanationRow:
        """Insert ``row`` and return it with the assigned database id."""
        cursor = self._db.execute(
            """
            INSERT INTO ai_explanations (
                event_id, provider, model, prompt_version, status, text,
                latency_ms, prompt_tokens, completion_tokens, created_ts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row.event_id,
                row.provider,
                row.model,
                row.prompt_version,
                row.status,
                row.text,
                row.latency_ms,
                row.prompt_tokens,
                row.completion_tokens,
                row.created_ts.isoformat(),
            ),
        )
        return replace(row, id=int(cursor.lastrowid or 0))

    def prune(self, before_ts: datetime | str) -> int:
        """Delete rows created before ``before_ts`` and return the count."""
        cutoff = before_ts.isoformat() if isinstance(before_ts, datetime) else before_ts
        cursor = self._db.execute("DELETE FROM ai_explanations WHERE created_ts < ?", (cutoff,))
        return int(cursor.rowcount or 0)


def _row_to_explanation(row: sqlite3.Row) -> ExplanationRow:
    """Rebuild an :class:`ExplanationRow` from a database row."""
    return ExplanationRow(
        id=int(row["id"]),
        event_id=str(row["event_id"]),
        provider=str(row["provider"]),
        model=str(row["model"]),
        prompt_version=str(row["prompt_version"]),
        status=str(row["status"]),
        text=str(row["text"]),
        latency_ms=_optional_int(row["latency_ms"]),
        prompt_tokens=_optional_int(row["prompt_tokens"]),
        completion_tokens=_optional_int(row["completion_tokens"]),
        created_ts=datetime.fromisoformat(row["created_ts"]),
    )


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return int(str(value))


__all__ = ["ExplanationCache", "ExplanationRow"]
