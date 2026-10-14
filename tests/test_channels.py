"""M13 — notification channel storage for the Notifications page.

A channel row is the only place a webhook URL, bot token, or SMTP password is kept, so
these tests are as much about *not* leaking as about reading and writing: a saved secret
stays put when the owner edits an unrelated field, the form vocabulary is validated before
anything is stored, and building the live channel picks the right concrete class.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from gilgamesh.channels import ChannelConfigError, ChannelStore
from gilgamesh.db import Database
from gilgamesh.models import Severity
from gilgamesh.notifiers.base import ChannelConfig, ChannelKind
from gilgamesh.notifiers.discord import DiscordChannel
from gilgamesh.notifiers.email import EmailChannel
from gilgamesh.notifiers.telegram import TelegramChannel


@pytest.fixture
def store(tmp_path: Path) -> Iterator[ChannelStore]:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    yield ChannelStore(database)
    database.close()


def test_absent_channel_is_not_configured(store: ChannelStore) -> None:
    assert store.get(ChannelKind.DISCORD) is None
    assert store.list() == []


def test_save_then_read_a_discord_channel(store: ChannelStore) -> None:
    record = store.save(
        ChannelKind.DISCORD,
        fields={"webhook_url": "https://discord.com/api/webhooks/1/abc"},
        min_severity=Severity.HIGH,
        enabled=True,
        quiet_start="22:00",
        quiet_end="07:00",
    )

    assert record.kind is ChannelKind.DISCORD
    assert record.id > 0
    assert record.min_severity is Severity.HIGH
    assert record.config["webhook_url"] == "https://discord.com/api/webhooks/1/abc"
    assert store.get(ChannelKind.DISCORD).config["webhook_url"] == record.config["webhook_url"]  # type: ignore[union-attr]


def test_save_is_upsert_by_kind(store: ChannelStore) -> None:
    store.save(ChannelKind.TELEGRAM, fields={"bot_token": "t1", "chat_id": "1"})
    store.save(ChannelKind.TELEGRAM, fields={"bot_token": "t2", "chat_id": "2"})

    assert len(store.list()) == 1
    assert store.get(ChannelKind.TELEGRAM).config["bot_token"] == "t2"  # type: ignore[union-attr]


def test_blank_secret_keeps_the_stored_one(store: ChannelStore) -> None:
    store.save(
        ChannelKind.DISCORD, fields={"webhook_url": "https://discord.com/api/webhooks/1/secret"}
    )

    # The UI never echoes a secret, so a blank field means "leave it alone".
    record = store.save(ChannelKind.DISCORD, fields={"webhook_url": ""})

    assert record.config["webhook_url"] == "https://discord.com/api/webhooks/1/secret"


def test_secret_fields_are_reported_as_set(store: ChannelStore) -> None:
    store.save(
        ChannelKind.EMAIL, fields={"smtp_host": "smtp.example.com", "smtp_password": "hunter2"}
    )

    record = store.get(ChannelKind.EMAIL)
    assert record is not None
    assert ChannelStore.secret_fields(ChannelKind.EMAIL) == ("smtp_password",)
    assert ChannelStore.is_secret_set(record, "smtp_password") is True


def test_invalid_severity_is_refused(store: ChannelStore) -> None:
    with pytest.raises(ChannelConfigError):
        store.save(ChannelKind.DISCORD, fields={}, min_severity="nope")  # type: ignore[arg-type]


def test_invalid_quiet_hours_are_refused(store: ChannelStore) -> None:
    with pytest.raises(ChannelConfigError):
        store.save(ChannelKind.DISCORD, fields={}, quiet_start="25:00", quiet_end="07:00")
    with pytest.raises(ChannelConfigError):
        store.save(ChannelKind.DISCORD, fields={}, quiet_start="22:00", quiet_end="7am")


def test_invalid_smtp_port_is_refused(store: ChannelStore) -> None:
    with pytest.raises(ChannelConfigError):
        store.save(ChannelKind.EMAIL, fields={"smtp_host": "h", "smtp_port": "not-a-port"})
    with pytest.raises(ChannelConfigError):
        store.save(ChannelKind.EMAIL, fields={"smtp_host": "h", "smtp_port": "70000"})


def test_recipients_are_split_and_trimmed(store: ChannelStore) -> None:
    record = store.save(
        ChannelKind.EMAIL,
        fields={"smtp_host": "h", "sender": "a@b.c", "recipients": "x@y.z, q@w.e"},
    )

    assert record.config["recipients"] == ["x@y.z", "q@w.e"]


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (ChannelKind.DISCORD, DiscordChannel),
        (ChannelKind.TELEGRAM, TelegramChannel),
        (ChannelKind.EMAIL, EmailChannel),
    ],
)
def test_build_notification_channel_matches_kind(
    kind: ChannelKind, expected: type, store: ChannelStore
) -> None:
    record = store.save(kind, fields={"webhook_url": "u", "bot_token": "t", "chat_id": "c"})

    channel = store.build_channel(record)

    assert isinstance(channel, expected)
    assert channel.kind is kind


def test_delete_removes_the_channel(store: ChannelStore) -> None:
    store.save(ChannelKind.TELEGRAM, fields={"bot_token": "t", "chat_id": "c"})

    store.delete(ChannelKind.TELEGRAM)

    assert store.get(ChannelKind.TELEGRAM) is None


def test_channels_survive_reopening_the_database(tmp_path: Path) -> None:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    ChannelStore(database).save(ChannelKind.DISCORD, fields={"webhook_url": "keep-me"})
    database.close()

    reopened = Database(tmp_path / "gilgamesh.db")
    reopened.initialize()
    record = ChannelStore(reopened).get(ChannelKind.DISCORD)
    assert record is not None and record.config["webhook_url"] == "keep-me"
    reopened.close()


def test_stored_config_is_scoped_to_the_kind(store: ChannelStore) -> None:
    """A Discord row must not retain stale SMTP fields from an earlier shape."""
    record = store.save(ChannelKind.DISCORD, fields={"webhook_url": "u"})

    assert set(record.config) == {"webhook_url"}


def test_config_round_trips_through_channel_config(store: ChannelStore) -> None:
    record = store.save(
        ChannelKind.EMAIL,
        fields={
            "smtp_host": "smtp.example.com",
            "smtp_port": "465",
            "smtp_username": "u",
            "smtp_password": "p",
            "smtp_use_tls": "on",
            "sender": "nids@example.com",
            "recipients": "me@example.com",
        },
    )

    config = store.to_channel_config(record)

    assert isinstance(config, ChannelConfig)
    assert config.smtp_host == "smtp.example.com"
    assert config.smtp_port == 465
    assert config.smtp_use_tls is True
    assert config.recipients == ("me@example.com",)
