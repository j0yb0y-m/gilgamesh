"""M11 — detection rule settings and allowlist (suppression) tests.

Decision D-017 governs this milestone: users toggle a **fixed catalogue** of built-in
rules and set **typed, bounded** parameters. There is no user-supplied regex and no
free-text rule authoring. Python's ``re`` has no timeout, so a user regex is a
remote-triggerable CPU exhaustion bug in a box whose whole job is to stay up — and a
free-text Suricata rule is a rule-injection path into ``disable.conf``.

So the properties tested here are mostly negative: values that must be rejected.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.rules import (
    ParamSpec,
    RuleCatalogue,
    RuleConfigService,
    RuleDefinition,
    RuleParamError,
    SuppressionField,
    default_catalogue,
)


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    yield database
    database.close()


@pytest.fixture
def service(db: Database) -> RuleConfigService:
    return RuleConfigService(db, default_catalogue())


def make_event(**overrides: object) -> Event:
    fields: dict[str, object] = {
        "type": EventType.ARP_SPOOF,
        "severity": Severity.HIGH,
        "detector": "arp",
        "summary": "Gateway MAC changed",
        "src_mac": "de:ad:be:ef:00:01",
        "src_ip": "10.0.0.2",
    }
    fields.update(overrides)
    return Event(**fields)  # type: ignore[arg-type]


# --- catalogue ----------------------------------------------------------------


def test_catalogue_covers_every_mvp_detector(service: RuleConfigService) -> None:
    detectors = {definition.detector for definition in service.catalogue.definitions()}

    assert detectors == {"arp", "dns", "dhcp", "scan_flood", "inventory", "suricata"}


def test_every_rule_id_is_unique(service: RuleConfigService) -> None:
    ids = [definition.id for definition in service.catalogue.definitions()]

    assert len(ids) == len(set(ids))


def test_every_rule_documents_itself(service: RuleConfigService) -> None:
    for definition in service.catalogue.definitions():
        assert definition.name, definition.id
        assert definition.description, definition.id


def test_defaults_match_the_shipped_detector_defaults(service: RuleConfigService) -> None:
    setting = service.settings()["scan.vertical"]

    assert setting.enabled is True
    assert setting.params["port_threshold"] == 20


# --- toggling -----------------------------------------------------------------


def test_unknown_rule_cannot_be_toggled(service: RuleConfigService) -> None:
    with pytest.raises(RuleParamError):
        service.set_enabled("made.up.rule", False)


def test_a_rule_can_be_disabled(service: RuleConfigService) -> None:
    service.set_enabled("arp.gateway_mac_changed", False)

    assert service.settings()["arp.gateway_mac_changed"].enabled is False


def test_a_rule_can_be_re_enabled(service: RuleConfigService) -> None:
    service.set_enabled("arp.gateway_mac_changed", False)
    service.set_enabled("arp.gateway_mac_changed", True)

    assert service.settings()["arp.gateway_mac_changed"].enabled is True


# --- typed parameters ---------------------------------------------------------


def test_int_parameter_round_trips(service: RuleConfigService) -> None:
    service.set_params("scan.vertical", {"port_threshold": "40"})

    assert service.settings()["scan.vertical"].params["port_threshold"] == 40


def test_float_parameter_round_trips(service: RuleConfigService) -> None:
    service.set_params("scan.vertical", {"scan_window": "25.5"})

    assert service.settings()["scan.vertical"].params["scan_window"] == 25.5


def test_bool_parameter_round_trips(service: RuleConfigService) -> None:
    service.set_params("dns.spoofing", {"conflicting_answers": "0"})

    assert service.settings()["dns.spoofing"].params["conflicting_answers"] is False


@pytest.mark.parametrize(
    "bad",
    ["0", "-5", "100000", "abc", "", "3.5"],
)
def test_out_of_range_or_non_numeric_int_is_rejected(service: RuleConfigService, bad: str) -> None:
    with pytest.raises(RuleParamError):
        service.set_params("scan.vertical", {"port_threshold": bad})


def test_unknown_parameter_is_rejected(service: RuleConfigService) -> None:
    with pytest.raises(RuleParamError):
        service.set_params("scan.vertical", {"nope": "1"})


def test_parameter_for_the_wrong_rule_is_rejected(service: RuleConfigService) -> None:
    with pytest.raises(RuleParamError):
        service.set_params("scan.vertical", {"discover_threshold": "1"})


def test_enum_parameter_rejects_unknown_choice(service: RuleConfigService) -> None:
    service.set_params("dns.spoofing", {"sensitivity": "strict"})
    assert service.settings()["dns.spoofing"].params["sensitivity"] == "strict"

    with pytest.raises(RuleParamError):
        service.set_params("dns.spoofing", {"sensitivity": "paranoid"})


def test_rejected_value_does_not_change_stored_state(service: RuleConfigService) -> None:
    before = service.settings()["scan.vertical"].params["port_threshold"]

    with pytest.raises(RuleParamError):
        service.set_params("scan.vertical", {"port_threshold": "999999"})

    assert service.settings()["scan.vertical"].params["port_threshold"] == before


# --- allowlists / suppressions ------------------------------------------------


def test_suppression_silences_a_matching_event(service: RuleConfigService) -> None:
    service.add_suppression(
        "arp.gateway_mac_changed", SuppressionField.SRC_MAC, "DE:AD:BE:EF:00:01"
    )

    assert service.is_suppressed(make_event()) is True


def test_suppression_does_not_silence_other_devices(service: RuleConfigService) -> None:
    service.add_suppression(
        "arp.gateway_mac_changed", SuppressionField.SRC_MAC, "aa:bb:cc:00:00:01"
    )

    assert service.is_suppressed(make_event()) is False


def test_suppression_is_scoped_to_its_rule(service: RuleConfigService) -> None:
    service.add_suppression("dns.spoofing", SuppressionField.SRC_MAC, "de:ad:be:ef:00:01")

    assert service.is_suppressed(make_event()) is False


def test_suppression_by_rule_any_covers_that_rule(service: RuleConfigService) -> None:
    service.add_suppression("arp.gateway_mac_changed", SuppressionField.ANY, "whatever")

    assert service.is_suppressed(make_event()) is True


def test_suppression_by_ip_is_supported(service: RuleConfigService) -> None:
    service.add_suppression("arp.gateway_mac_changed", SuppressionField.SRC_IP, "10.0.0.2")

    assert service.is_suppressed(make_event()) is True


def test_suppression_values_are_normalised(service: RuleConfigService) -> None:
    service.add_suppression(
        "arp.gateway_mac_changed", SuppressionField.SRC_MAC, "de-ad-be-ef-00-01"
    )

    assert service.is_suppressed(make_event()) is True


def test_suppression_can_be_removed(service: RuleConfigService) -> None:
    suppression = service.add_suppression(
        "arp.gateway_mac_changed", SuppressionField.SRC_MAC, "de:ad:be:ef:00:01"
    )

    service.remove_suppression(suppression.id)

    assert service.is_suppressed(make_event()) is False
    assert service.suppressions() == []


def test_invalid_suppression_value_is_rejected(service: RuleConfigService) -> None:
    with pytest.raises(RuleParamError):
        service.add_suppression("arp.gateway_mac_changed", SuppressionField.SRC_MAC, "not-a-mac")

    with pytest.raises(RuleParamError):
        service.add_suppression(
            "arp.gateway_mac_changed", SuppressionField.SRC_IP, "999.999.999.999"
        )


def test_suppression_for_unknown_rule_is_rejected(service: RuleConfigService) -> None:
    with pytest.raises(RuleParamError):
        service.add_suppression("made.up", SuppressionField.SRC_MAC, "de:ad:be:ef:00:01")


def test_removing_unknown_suppression_is_rejected(service: RuleConfigService) -> None:
    with pytest.raises(RuleParamError):
        service.remove_suppression(999)


def test_no_regex_is_ever_accepted(service: RuleConfigService) -> None:
    """Pattern metacharacters are stored literally; nothing is ever compiled."""
    service.add_suppression("arp.gateway_mac_changed", SuppressionField.DETECTOR, ".*")

    assert service.suppressions()[0].value == ".*"
    assert service.is_suppressed(make_event()) is False


# --- wiring detectors to the stored settings ---------------------------------


def test_effective_params_feed_the_detector_config(service: RuleConfigService) -> None:
    service.set_params("scan.vertical", {"port_threshold": "35"})

    params = service.effective_params("scan.vertical")

    assert params["port_threshold"] == 35


def test_catalogue_rejects_duplicate_ids() -> None:
    definition = RuleDefinition(
        id="dup.rule",
        name="Duplicate",
        description="A rule defined twice.",
        detector="arp",
        params=(),
    )

    with pytest.raises(ValueError, match="duplicate"):
        RuleCatalogue([definition, definition])


def test_param_spec_rejects_impossible_bounds() -> None:
    with pytest.raises(ValueError, match="exceeds maximum"):
        ParamSpec(name="threshold", kind="int", default=1, minimum=10, maximum=1)


def test_param_spec_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="kind"):
        ParamSpec(name="pattern", kind="regex", default="")


def test_rule_definition_param_lookup() -> None:
    definition = RuleDefinition(
        id="demo.rule",
        name="Demo",
        description="A rule used by the catalogue tests.",
        detector="arp",
        params=(ParamSpec(name="threshold", kind="int", default=5, minimum=1, maximum=9),),
    )

    assert definition.param("threshold") is not None
    assert definition.param("missing") is None
    assert definition.defaults() == {"threshold": 5}
