"""The provider API key is encrypted at rest and never leaves the box in clear.

The key file is the only secret that can decrypt the stored token; the database row
alone is useless. These tests pin the round trip, the file permissions, and the
failure posture: a missing or damaged key file returns ``None`` instead of crashing
or leaking the token.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from gilgamesh.ai.secrets import AiKeyStore
from gilgamesh.config import Settings
from gilgamesh.db import Database

SECRET = "sk-test-123-do-not-log-me"


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def key_path(tmp_path: Path) -> Path:
    return tmp_path / "private" / "ai.key"


@pytest.fixture
def store(database: Database, key_path: Path) -> AiKeyStore:
    return AiKeyStore(database, key_path)


def test_settings_exposes_the_key_path(tmp_path: Path) -> None:
    assert Settings(data_dir=tmp_path).ai_key_path == tmp_path / "ai.key"


def test_missing_row_is_not_set(store: AiKeyStore) -> None:
    assert store.is_set() is False
    assert store.get_key() is None


def test_key_round_trips_and_is_not_stored_in_plaintext(
    store: AiKeyStore, database: Database, key_path: Path, tmp_path: Path
) -> None:
    store.set_key(SECRET)

    assert store.get_key() == SECRET
    assert store.is_set() is True
    assert SECRET.encode() not in (tmp_path / "gilgamesh.db").read_bytes()
    assert key_path.stat().st_mode & 0o777 == 0o600
    assert key_path.parent.stat().st_mode & 0o777 == 0o700
    assert database.get_setting("ai_api_key") != SECRET


def test_missing_key_file_returns_none_without_crashing(store: AiKeyStore, key_path: Path) -> None:
    store.set_key(SECRET)
    key_path.unlink()

    assert store.get_key() is None
    assert store.is_set() is True


def test_corrupt_key_file_returns_none_and_logs_without_secrets(
    store: AiKeyStore, key_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store.set_key(SECRET)
    key_path.write_bytes(b"this is not a fernet key")

    with caplog.at_level(logging.WARNING, logger="gilgamesh.ai.secrets"):
        assert store.get_key() is None

    assert "AI key unavailable" in caplog.text
    assert SECRET not in caplog.text


def test_corrupt_token_returns_none_and_logs_without_secrets(
    store: AiKeyStore, database: Database, caplog: pytest.LogCaptureFixture
) -> None:
    store.set_key(SECRET)
    database.set_setting("ai_api_key", "not-a-fernet-token")

    with caplog.at_level(logging.WARNING, logger="gilgamesh.ai.secrets"):
        assert store.get_key() is None

    assert "AI key unavailable" in caplog.text
    assert "not-a-fernet-token" not in caplog.text
    assert SECRET not in caplog.text


def test_empty_key_is_refused(store: AiKeyStore) -> None:
    with pytest.raises(ValueError):
        store.set_key("")

    assert store.is_set() is False


def test_clear_key_removes_the_row_but_keeps_the_key_file(
    store: AiKeyStore, key_path: Path
) -> None:
    store.set_key(SECRET)

    store.clear_key()

    assert store.is_set() is False
    assert store.get_key() is None
    assert key_path.exists()


def test_two_stores_share_the_same_key_file(database: Database, key_path: Path) -> None:
    first = AiKeyStore(database, key_path)
    first.set_key("sk-first")
    original = key_path.read_bytes()

    second = AiKeyStore(database, key_path)
    assert second.get_key() == "sk-first"
    second.set_key("sk-second")

    assert key_path.read_bytes() == original
    assert first.get_key() == "sk-second"


def test_setting_a_key_never_logs_the_plaintext(
    store: AiKeyStore, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="gilgamesh.ai.secrets"):
        store.set_key(SECRET)
        assert store.get_key() == SECRET

    assert SECRET not in caplog.text
