"""Owner preferences for the Settings page (M13).

The Settings page collects things that are genuinely process-level *intent* — how long to
keep alerts, which mode the box is meant to run in, which interfaces are the LAN and WAN
side. None of it is applied to the host from here: changing a bridge or a NIC offload is
a documented Pi step the owner runs themselves (the web tier is unprivileged and C1/C2
forbid the app doing it). Storing the intent is still useful, because the wizard, the
sensor unit, and the docs all read the same answers.

Every field is bounded and validated on the way in, so a value that later reaches a
template or a generated file can never carry a path separator or a shell metacharacter.
"""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from gilgamesh.db import Database

_SETTINGS_KEY = "preferences"
#: Linux interface names are at most 15 characters and exclude '/' and whitespace.
_IFACE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_NETWORK_MODES = frozenset({"bridge", "span"})
_HTTPS_MODES = frozenset({"off", "self-signed", "provided"})


class PreferenceError(ValueError):
    """A submitted preference was not acceptable. The message is safe to show the owner."""


class Preferences(BaseModel):
    """The owner's choices, with the bounds enforced by the model itself."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    retention_days: int = 30
    network_mode: str = "bridge"
    lan_interface: str = "eth1"
    wan_interface: str = "eth0"
    https_mode: str = "off"

    @field_validator("retention_days")
    @classmethod
    def _bounded_retention(cls, value: int) -> int:
        if not 1 <= value <= 365:
            raise ValueError("retention must be between 1 and 365 days")
        return value

    @field_validator("network_mode")
    @classmethod
    def _known_mode(cls, value: str) -> str:
        if value not in _NETWORK_MODES:
            raise ValueError("network mode must be bridge or span")
        return value

    @field_validator("https_mode")
    @classmethod
    def _known_https(cls, value: str) -> str:
        if value not in _HTTPS_MODES:
            raise ValueError("HTTPS mode must be off, self-signed, or provided")
        return value

    @field_validator("lan_interface", "wan_interface")
    @classmethod
    def _valid_iface(cls, value: str) -> str:
        if not _IFACE.match(value):
            raise ValueError("interface names are 1-15 letters, digits, '.', '_' or '-'")
        return value


class PreferencesStore:
    """Read and update :class:`Preferences` in the ``app_settings`` table."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def get(self) -> Preferences:
        """The stored preferences, or the defaults when nothing has been saved."""
        rows = self._db.query("SELECT value FROM app_settings WHERE key = ?", (_SETTINGS_KEY,))
        if not rows:
            return Preferences()
        try:
            return Preferences.model_validate(json.loads(rows[0]["value"]))
        except (ValueError, ValidationError):
            # A hand-edited or corrupted row must not brick the page; fall back to
            # defaults rather than raising on every request.
            return Preferences()

    def update(self, **fields: object) -> Preferences:
        """Validate and persist a partial update, returning the new state.

        Validation happens on a merged copy, so a rejected update leaves the stored row
        exactly as it was — a bad retention value cannot half-apply.
        """
        merged: dict[str, object] = {**self.get().model_dump(), **fields}
        try:
            updated = Preferences.model_validate(merged)
        except ValidationError as exc:
            raise PreferenceError(_first_message(exc)) from exc
        self._db.execute(
            """
            INSERT INTO app_settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (_SETTINGS_KEY, json.dumps(updated.model_dump())),
        )
        return updated


def _first_message(exc: ValidationError) -> str:
    """The first human-readable validation message, without Pydantic's URL noise."""
    errors = exc.errors()
    if not errors:
        return "invalid value"
    message = str(errors[0].get("msg", "invalid value"))
    return message.removeprefix("Value error, ")


__all__ = ["PreferenceError", "Preferences", "PreferencesStore"]
