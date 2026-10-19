"""The rule gate: the bridge between the owner's choices and what the sensor announces.

These tests cover the decisions the Rules and Allowlist pages promise: a switch that is
off is off, an allowlist entry silences only its own rule, a trusted device raises no
"new device" alert, and none of it can be read from the database quickly enough to
matter while an attack is in progress.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.rules import (
    RuleConfigService,
    RuleSetting,
    SuppressionField,
    default_catalogue,
)
from gilgamesh.sensors.gate import RuleGate


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    yield database
    database.close()


@pytest.fixture
def rules(db: Database) -> RuleConfigService:
    return RuleConfigService(db, default_catalogue())


@pytest.fixture
def devices(db: Database) -> DeviceStore:
    return DeviceStore(db)


def make_event(**overrides: object) -> Event:
    fields: dict[str, object] = {
        "type": EventType.ARP_SPOOF,
        "severity": Severity.HIGH,
        "detector": "arp",
        "summary": "Gateway MAC changed",
        "src_mac": "de:ad:be:ef:00:01",
        "src_ip": "10.0.0.2",
        "details": {"reason": "gateway_mac_changed"},
    }
    fields.update(overrides)
    return Event(**fields)  # type: ignore[arg-type]


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_a_disabled_rule_drops_only_its_events(rules: RuleConfigService) -> None:
    gate = RuleGate(rules)
    rules.set_enabled("arp.gateway_mac_changed", False)

    assert gate.allows(make_event()) is False
    assert (
        gate.allows(
            make_event(
                summary="IP/MAC conflict",
                details={"reason": "ip_mac_conflict"},
            )
        )
        is True
    )


def test_an_event_with_no_rule_of_its_own_is_never_gated(rules: RuleConfigService) -> None:
    """The v1 catalogue has no switch for Ethernet-source mismatches; nothing may hide them."""
    for rule_id in ("arp.gateway_mac_changed", "arp.ip_mac_conflict", "arp.gratuitous_flood"):
        rules.set_enabled(rule_id, False)
    gate = RuleGate(rules)

    assert gate.allows(make_event(details={"reason": "ethernet_source_mismatch"})) is True


def test_allowlist_silences_its_rule_and_no_other(rules: RuleConfigService) -> None:
    rules.add_suppression("arp.gateway_mac_changed", SuppressionField.SRC_MAC, "de:ad:be:ef:00:01")
    gate = RuleGate(rules)

    assert gate.allows(make_event()) is False
    # The same speaker triggering a different rule is a different alert.
    assert gate.allows(make_event(details={"reason": "ip_mac_conflict"})) is True


def test_trusted_device_is_not_reported_as_new(
    rules: RuleConfigService, devices: DeviceStore
) -> None:
    devices.upsert("de:ad:be:ef:00:01", ip="10.0.0.2")
    devices.set_trusted("de:ad:be:ef:00:01", True)
    gate = RuleGate(rules, devices)

    new_device = make_event(
        type=EventType.NEW_DEVICE,
        severity=Severity.LOW,
        detector="inventory",
        summary="New device",
        details={"reason": "new_device"},
    )
    assert gate.allows(new_device) is False

    other_device = new_device.model_copy(update={"src_mac": "de:ad:be:ef:00:02"})
    assert gate.allows(other_device) is True


def test_suricata_minimum_severity_filters(rules: RuleConfigService) -> None:
    rules.set_params("suricata.alerts", {"min_severity": "high"})
    gate = RuleGate(rules)

    low = make_event(
        type=EventType.SURICATA_ALERT,
        severity=Severity.LOW,
        detector="suricata",
        summary="ET INFO something",
        details={},
    )
    critical = low.model_copy(update={"severity": Severity.CRITICAL})

    assert gate.allows(low) is False
    assert gate.allows(critical) is True


def test_dns_conflicting_answers_switch_silences_that_check(rules: RuleConfigService) -> None:
    rules.set_params("dns.spoofing", {"conflicting_answers": False})
    gate = RuleGate(rules)

    conflicting = make_event(
        type=EventType.DNS_SPOOF,
        detector="dns",
        summary="Conflicting answers",
        details={"reason": "conflicting_answers"},
    )
    forged = conflicting.model_copy(
        update={"details": {"reason": "response_without_matching_query"}}
    )

    assert gate.allows(conflicting) is False
    assert gate.allows(forged) is True


def test_settings_are_cached_until_the_refresh_interval(rules: RuleConfigService) -> None:
    clock = _Clock()
    gate = RuleGate(rules, refresh_seconds=30.0, clock=clock)

    assert gate.allows(make_event()) is True
    rules.set_enabled("arp.gateway_mac_changed", False)

    # Inside the window the cached snapshot is still in force…
    clock.advance(29.0)
    assert gate.allows(make_event()) is True

    # …and once it expires the new one is read without a restart.
    clock.advance(2.0)
    assert gate.allows(make_event()) is False


class _BrokenRules:
    """A rules service whose reads fail after the first successful one."""

    def __init__(self, settings: dict[str, RuleSetting]) -> None:
        self._settings = settings
        self.broken = False

    def settings(self) -> dict[str, RuleSetting]:
        if self.broken:
            raise RuntimeError("database is locked")
        return self._settings

    def suppressions(self) -> list[object]:
        return []


def test_unreadable_settings_keep_the_previous_snapshot() -> None:
    """An unreadable rule book must not silently turn every rule back on."""
    settings = {"arp.gateway_mac_changed": RuleSetting("arp.gateway_mac_changed", False, {})}
    stub = _BrokenRules(settings)
    clock = _Clock()
    gate = RuleGate(cast(RuleConfigService, stub), refresh_seconds=1.0, clock=clock)

    assert gate.allows(make_event()) is False
    stub.broken = True
    clock.advance(5.0)

    # The refresh failed; the cached "off" survives rather than defaulting to on.
    assert gate.allows(make_event()) is False
