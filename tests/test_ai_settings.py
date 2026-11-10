"""Opt-in AI explanation settings and the provider presets they select.

AI is off until the owner turns it on, and the default posture is to redact every
identifier. These tests pin that posture, the field bounds, and the store's
atomic-update property: a rejected value must never half-apply.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from gilgamesh.ai.settings import (
    PRESETS,
    AiSettings,
    AiSettingsError,
    AiSettingsStore,
    ProviderPreset,
    preset,
)
from gilgamesh.db import Database


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def store(database: Database) -> AiSettingsStore:
    return AiSettingsStore(database)


def test_defaults_are_off_and_redact_everything() -> None:
    settings = AiSettings()

    assert settings.enabled is False
    assert (settings.redact_mac, settings.redact_hostname, settings.redact_ips) == (
        True,
        True,
        True,
    )
    assert settings.preset == "openai"
    assert settings.kind == "openai"
    assert settings.base_url == "https://api.openai.com/v1"
    assert settings.model == "gpt-4o-mini"
    assert settings.max_tokens == 400
    assert settings.timeout_s == 20.0
    assert settings.local_provider is False


def test_presets_cover_every_documented_provider() -> None:
    ids = {item.id for item in PRESETS}

    assert ids >= {
        "openai",
        "anthropic",
        "gemini",
        "groq",
        "mistral",
        "openrouter",
        "ollama",
        "llama_cpp",
        "custom",
    }


def test_presets_are_well_formed_and_flag_local_providers() -> None:
    assert len({item.id for item in PRESETS}) == len(PRESETS)
    for item in PRESETS:
        assert isinstance(item, ProviderPreset)
        assert item.id
        assert item.label
        assert item.kind in {"openai", "anthropic"}
        assert item.base_url.startswith("http")
        assert item.model
    by_id = {item.id: item for item in PRESETS}
    assert by_id["ollama"].local_only is True
    assert by_id["ollama"].requires_key is False
    assert by_id["llama_cpp"].local_only is True
    assert by_id["llama_cpp"].requires_key is False
    assert by_id["openai"].requires_key is True
    assert by_id["anthropic"].kind == "anthropic"


def test_preset_lookup_rejects_unknown_ids() -> None:
    assert preset("openai").id == "openai"

    with pytest.raises(AiSettingsError):
        preset("no-such-provider")


def test_missing_row_returns_defaults(store: AiSettingsStore) -> None:
    assert store.get() == AiSettings()


def test_bounds_and_partial_update_are_atomic(store: AiSettingsStore) -> None:
    updated = store.update(enabled=True, max_tokens=600)

    assert updated.enabled is True
    assert updated.max_tokens == 600

    with pytest.raises(AiSettingsError):
        store.update(max_tokens=5000)

    assert store.get().max_tokens == 600
    assert store.get().enabled is True


@pytest.mark.parametrize("value", [99, 1001])
def test_max_tokens_is_bounded(store: AiSettingsStore, value: int) -> None:
    with pytest.raises(AiSettingsError):
        store.update(max_tokens=value)


@pytest.mark.parametrize("value", [4.9, 60.1])
def test_timeout_is_bounded(store: AiSettingsStore, value: float) -> None:
    with pytest.raises(AiSettingsError):
        store.update(timeout_s=value)


def test_timeout_accepts_the_boundaries(store: AiSettingsStore) -> None:
    assert store.update(timeout_s=5).timeout_s == 5.0
    assert store.update(timeout_s=60).timeout_s == 60.0


@pytest.mark.parametrize("value", ["", "x" * 201])
def test_model_is_bounded(store: AiSettingsStore, value: str) -> None:
    with pytest.raises(AiSettingsError):
        store.update(model=value)


@pytest.mark.parametrize("value", ["", "https://example.test/" + "x" * 500])
def test_base_url_is_bounded(store: AiSettingsStore, value: str) -> None:
    with pytest.raises(AiSettingsError):
        store.update(base_url=value)


def test_unknown_kind_and_preset_are_refused(store: AiSettingsStore) -> None:
    with pytest.raises(AiSettingsError):
        store.update(kind="gemini")
    with pytest.raises(AiSettingsError):
        store.update(preset="no-such-provider")

    assert store.get() == AiSettings()


def test_update_persists_and_survives_reopening(tmp_path: Path) -> None:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    AiSettingsStore(database).update(
        enabled=True,
        preset="ollama",
        kind="openai",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        local_provider=True,
    )
    database.close()

    reopened = Database(tmp_path / "gilgamesh.db")
    reopened.initialize()
    try:
        settings = AiSettingsStore(reopened).get()
        assert settings.enabled is True
        assert settings.preset == "ollama"
        assert settings.base_url == "http://127.0.0.1:11434/v1"
        assert settings.model == "llama3.2"
        assert settings.local_provider is True
    finally:
        reopened.close()


def test_corrupt_json_row_falls_back_to_defaults(database: Database) -> None:
    database.set_setting("ai_settings", "{not json")

    assert AiSettingsStore(database).get() == AiSettings()


def test_non_object_json_row_falls_back_to_defaults(database: Database) -> None:
    database.set_setting("ai_settings", json.dumps(["enabled"]))

    assert AiSettingsStore(database).get() == AiSettings()


def test_out_of_bounds_stored_row_falls_back_to_defaults(database: Database) -> None:
    database.set_setting(
        "ai_settings",
        json.dumps({"enabled": True, "max_tokens": 5000}),
    )

    assert AiSettingsStore(database).get() == AiSettings()


def test_reset_restores_defaults(store: AiSettingsStore) -> None:
    store.update(enabled=True, redact_mac=False, max_tokens=900)

    restored = store.reset()

    assert restored == AiSettings()
    assert store.get() == AiSettings()
