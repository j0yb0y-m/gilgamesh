"""The explanation cache keeps successes, ignores failures, and prunes by age.

A cached explanation is a convenience, not evidence: only rows with
``status='ok'`` may be returned, and an error row must never mask an older
successful answer. The cache key includes the provider, model, and prompt
version so changing any of them starts a fresh explanation.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from gilgamesh.ai.cache import ExplanationCache, ExplanationRow
from gilgamesh.db import Database

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def cache(database: Database) -> ExplanationCache:
    return ExplanationCache(database)


def row(**overrides: object) -> ExplanationRow:
    values: dict[str, object] = {
        "id": None,
        "event_id": "event-1",
        "provider": "openai",
        "model": "gpt-test",
        "prompt_version": "behaviour-ai-v1",
        "status": "ok",
        "text": "The camera uploaded a backup.",
        "latency_ms": 12,
        "prompt_tokens": 10,
        "completion_tokens": 5,
        "created_ts": NOW,
    }
    values.update(overrides)
    return ExplanationRow(**values)  # type: ignore[arg-type]


def test_put_returns_the_row_with_its_new_id(cache: ExplanationCache) -> None:
    saved = cache.put(row())

    assert saved.id is not None
    loaded = cache.get("event-1", "openai", "gpt-test", "behaviour-ai-v1")
    assert loaded == saved


def test_get_ignores_error_rows(cache: ExplanationCache) -> None:
    cache.put(row(status="error", text=""))

    assert cache.get("event-1", "openai", "gpt-test", "behaviour-ai-v1") is None


def test_get_is_keyed_by_event_provider_model_and_prompt_version(
    cache: ExplanationCache,
) -> None:
    cache.put(row())

    assert cache.get("other-event", "openai", "gpt-test", "behaviour-ai-v1") is None
    assert cache.get("event-1", "anthropic", "gpt-test", "behaviour-ai-v1") is None
    assert cache.get("event-1", "openai", "other-model", "behaviour-ai-v1") is None
    assert cache.get("event-1", "openai", "gpt-test", "other-version") is None


def test_latest_successful_row_wins(cache: ExplanationCache) -> None:
    cache.put(row(text="first"))
    cache.put(row(text="second"))

    loaded = cache.get("event-1", "openai", "gpt-test", "behaviour-ai-v1")

    assert loaded is not None
    assert loaded.text == "second"


def test_prune_deletes_rows_older_than_the_cutoff(cache: ExplanationCache) -> None:
    cache.put(row(text="old", created_ts=NOW - timedelta(days=100)))
    cache.put(row(text="new", created_ts=NOW))

    removed = cache.prune(NOW - timedelta(days=90))

    assert removed == 1
    loaded = cache.get("event-1", "openai", "gpt-test", "behaviour-ai-v1")
    assert loaded is not None
    assert loaded.text == "new"


def test_prune_accepts_an_iso_cutoff(cache: ExplanationCache) -> None:
    cache.put(row(text="old", created_ts=NOW - timedelta(days=100)))

    removed = cache.prune((NOW - timedelta(days=90)).isoformat())

    assert removed == 1
    assert cache.get("event-1", "openai", "gpt-test", "behaviour-ai-v1") is None


def test_put_preserves_the_error_status_and_empty_text(cache: ExplanationCache) -> None:
    cache.put(row(status="error", text="", latency_ms=None, prompt_tokens=None))

    rows = cache.get("event-1", "openai", "gpt-test", "behaviour-ai-v1")
    assert rows is None
