"""Opt-in AI explanation settings and the provider presets they select.

The model is deliberately plain data. A preset only fills the form; the owner can
edit the URL and the model afterwards, because provider model names change faster
than this code does. Everything is validated on the way in, so a stored row can
never smuggle an out-of-range token budget or an unknown provider kind into a
request.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from gilgamesh.db import Database

_SETTINGS_KEY = "ai_settings"
_PROVIDER_KINDS = frozenset({"openai", "anthropic"})
ProviderKind = Literal["openai", "anthropic"]


class AiSettingsError(ValueError):
    """A submitted AI setting was not acceptable. Safe to show the owner."""


@dataclass(frozen=True, slots=True)
class ProviderPreset:
    """One entry in the provider dropdown.

    ``requires_key`` is false for local runtimes, and ``local_only`` permits a
    plain-``http`` URL and a private/loopback address (checked by the adapter).
    """

    id: str
    label: str
    kind: ProviderKind
    base_url: str
    model: str
    requires_key: bool = True
    local_only: bool = False


#: Presets are data, not code: the UI can render the dropdown from this tuple.
PRESETS: tuple[ProviderPreset, ...] = (
    ProviderPreset(
        id="openai",
        label="OpenAI",
        kind="openai",
        base_url="https://api.openai.com/v1",
        model="gpt-4o-mini",
    ),
    ProviderPreset(
        id="anthropic",
        label="Anthropic",
        kind="anthropic",
        base_url="https://api.anthropic.com/v1",
        model="claude-sonnet-4-5",
    ),
    ProviderPreset(
        id="gemini",
        label="Google Gemini",
        kind="openai",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        model="gemini-2.5-flash",
    ),
    ProviderPreset(
        id="groq",
        label="Groq",
        kind="openai",
        base_url="https://api.groq.com/openai/v1",
        model="llama-3.3-70b-versatile",
    ),
    ProviderPreset(
        id="mistral",
        label="Mistral",
        kind="openai",
        base_url="https://api.mistral.ai/v1",
        model="mistral-small-latest",
    ),
    ProviderPreset(
        id="openrouter",
        label="OpenRouter",
        kind="openai",
        base_url="https://openrouter.ai/api/v1",
        model="openrouter/auto",
    ),
    ProviderPreset(
        id="ollama",
        label="Ollama (local)",
        kind="openai",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        requires_key=False,
        local_only=True,
    ),
    ProviderPreset(
        id="llama_cpp",
        label="llama.cpp (local)",
        kind="openai",
        base_url="http://127.0.0.1:8080/v1",
        model="local-model",
        requires_key=False,
        local_only=True,
    ),
    ProviderPreset(
        id="custom",
        label="Custom",
        kind="openai",
        base_url="https://example.invalid/v1",
        model="model",
    ),
)

_PRESETS_BY_ID = {item.id: item for item in PRESETS}


def preset(preset_id: str) -> ProviderPreset:
    """Return the preset with ``preset_id`` or raise :class:`AiSettingsError`."""
    try:
        return _PRESETS_BY_ID[preset_id]
    except KeyError as exc:
        raise AiSettingsError(f"unknown provider preset: {preset_id}") from exc


class AiSettings(BaseModel):
    """The owner's AI explanation choices, bounded by the model itself."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = False
    preset: str = "openai"
    kind: ProviderKind = "openai"
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    max_tokens: int = 400
    timeout_s: float = 20.0
    local_provider: bool = False
    redact_mac: bool = True
    redact_hostname: bool = True
    redact_ips: bool = True

    @field_validator("preset")
    @classmethod
    def _known_preset(cls, value: str) -> str:
        if value not in _PRESETS_BY_ID:
            raise ValueError("unknown provider preset")
        return value

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, value: str) -> str:
        if value not in _PROVIDER_KINDS:
            raise ValueError("provider kind must be openai or anthropic")
        return value

    @field_validator("model")
    @classmethod
    def _bounded_model(cls, value: str) -> str:
        value = value.strip()
        if not 1 <= len(value) <= 200:
            raise ValueError("model must be 1-200 characters")
        return value

    @field_validator("base_url")
    @classmethod
    def _bounded_base_url(cls, value: str) -> str:
        value = value.strip()
        if not 1 <= len(value) <= 500:
            raise ValueError("base URL must be 1-500 characters")
        return value

    @field_validator("max_tokens")
    @classmethod
    def _bounded_max_tokens(cls, value: int) -> int:
        if not 100 <= value <= 1000:
            raise ValueError("max tokens must be between 100 and 1000")
        return value

    @field_validator("timeout_s")
    @classmethod
    def _bounded_timeout(cls, value: float) -> float:
        if not 5 <= value <= 60:
            raise ValueError("timeout must be between 5 and 60 seconds")
        return value


class AiSettingsStore:
    """Read and update :class:`AiSettings` in the ``app_settings`` table."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def get(self) -> AiSettings:
        """The stored settings, or defaults when nothing valid has been saved."""
        raw = self._db.get_setting(_SETTINGS_KEY)
        if raw is None:
            return AiSettings()
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                return AiSettings()
            return AiSettings.model_validate(data)
        except (ValueError, ValidationError):
            # A hand-edited or corrupted row must not brick Settings; fall back to
            # the safe defaults rather than raising on every request.
            return AiSettings()

    def update(self, **fields: object) -> AiSettings:
        """Validate and persist a partial update, returning the new state.

        Validation runs on a merged copy, so a rejected value leaves the stored
        row exactly as it was.
        """
        updated = validate_settings(self.get(), **fields)
        self._db.set_setting(_SETTINGS_KEY, json.dumps(updated.model_dump()))
        return updated

    def reset(self) -> AiSettings:
        """Write and return the defaults, which means AI off and all redaction on."""
        defaults = AiSettings()
        self._db.set_setting(_SETTINGS_KEY, json.dumps(defaults.model_dump()))
        return defaults


def validate_settings(current: AiSettings, **fields: object) -> AiSettings:
    """Validate a partial update against ``current`` without persisting it."""
    merged: dict[str, object] = {**current.model_dump(), **fields}
    try:
        return AiSettings.model_validate(merged)
    except ValidationError as exc:
        raise AiSettingsError(_first_message(exc)) from exc


def _first_message(exc: ValidationError) -> str:
    """The first human-readable validation message, without Pydantic's URL noise."""
    errors = exc.errors()
    if not errors:
        return "invalid value"
    message = str(errors[0].get("msg", "invalid value"))
    return message.removeprefix("Value error, ")


__all__ = [
    "PRESETS",
    "AiSettings",
    "AiSettingsError",
    "AiSettingsStore",
    "ProviderKind",
    "ProviderPreset",
    "preset",
    "validate_settings",
]
