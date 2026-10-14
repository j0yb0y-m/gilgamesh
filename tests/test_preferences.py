"""M13 — persisted owner preferences (the Settings page).

Only values with bounded, enumerable shapes are stored here, and the validator rejects
anything else *before* it reaches the database. Interface names in particular are
validated even though the app never applies them itself: they are displayed back and may
one day be written into a documented Pi step, so a value containing a slash or a space
must not be storable.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError

from gilgamesh.db import Database
from gilgamesh.preferences import PreferenceError, Preferences, PreferencesStore


@pytest.fixture
def store(tmp_path: Path) -> Iterator[PreferencesStore]:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    yield PreferencesStore(database)
    database.close()


def test_defaults_match_the_plan(store: PreferencesStore) -> None:
    prefs = store.get()

    assert prefs.retention_days == 30
    assert prefs.network_mode == "bridge"
    assert prefs.https_mode == "off"


def test_update_persists_and_survives_a_restart(tmp_path: Path) -> None:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    PreferencesStore(database).update(retention_days=14, network_mode="span", lan_interface="enx1")
    database.close()

    reopened = Database(tmp_path / "gilgamesh.db")
    reopened.initialize()
    prefs = PreferencesStore(reopened).get()
    assert prefs.retention_days == 14
    assert prefs.network_mode == "span"
    assert prefs.lan_interface == "enx1"
    reopened.close()


def test_update_only_changes_given_fields(store: PreferencesStore) -> None:
    store.update(retention_days=7)

    assert store.update(lan_interface="eth9").retention_days == 7


@pytest.mark.parametrize("bad", [0, 366, -1, 100_000])
def test_retention_is_bounded(store: PreferencesStore, bad: int) -> None:
    with pytest.raises(PreferenceError):
        store.update(retention_days=bad)


def test_unknown_network_mode_is_refused(store: PreferencesStore) -> None:
    with pytest.raises(PreferenceError):
        store.update(network_mode="router")


def test_unknown_https_mode_is_refused(store: PreferencesStore) -> None:
    with pytest.raises(PreferenceError):
        store.update(https_mode="letsencrypt")


@pytest.mark.parametrize("bad", ["eth0/../etc", "with space", "x" * 16, ""])
def test_interface_names_are_validated(store: PreferencesStore, bad: str) -> None:
    with pytest.raises(PreferenceError):
        store.update(lan_interface=bad)


def test_invalid_update_leaves_stored_state_untouched(store: PreferencesStore) -> None:
    store.update(retention_days=45)

    with pytest.raises(PreferenceError):
        store.update(retention_days=999)

    assert store.get().retention_days == 45


def test_preferences_model_rejects_out_of_range() -> None:
    with pytest.raises(ValidationError):
        Preferences(retention_days=0)
