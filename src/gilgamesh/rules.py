"""Detection rule catalogue, typed settings, and allowlist suppressions.

**The design rule that shapes this module is D-017: the owner configures a *fixed
catalogue* of built-in rules with *typed, bounded* parameters. There is no user-supplied
regular expression and no free-text rule authoring.**

Both omissions are deliberate:

* **No user regex.** Python's :mod:`re` has no timeout. A pattern a user pastes into
  their own NIDS is a CPU-exhaustion bug on the box whose entire job is to stay up — and
  with a small box and a single core, that is a self-inflicted denial of service. The
  allowlist below matches on **exact, normalised values** (a MAC, an IP, a rule id), which
  cannot backtrack.
* **No free-text Suricata rules.** A hand-written rule is a rule-injection path into
  ``disable.conf`` and into Suricata's own configuration. Values here are validated
  integers, floats, booleans, and enum choices, and only integers can ever reach a
  generated rule file (see :mod:`gilgamesh.sensors.suricata_ingest`).

Every parameter is bounded, so a mistyped ``port_threshold`` cannot disable detection by
accident or by design.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from gilgamesh.db import Database
from gilgamesh.models import Event, EventType
from gilgamesh.util.net import normalize_mac

logger = logging.getLogger(__name__)

_KINDS = frozenset({"int", "float", "bool", "enum"})


class SuppressionField(StrEnum):
    """Which field of an event a suppression matches on."""

    #: Any rule, any value — a blanket mute for one rule.
    ANY = "any"
    SRC_MAC = "src_mac"
    SRC_IP = "src_ip"
    DST_IP = "dst_ip"
    DETECTOR = "detector"


class RuleParamError(ValueError):
    """Raised when a rule parameter or suppression value is invalid."""


@dataclass(frozen=True, slots=True)
class ParamSpec:
    """The type, bounds, and default of one rule parameter."""

    name: str
    kind: str
    default: int | float | bool | str
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple[str, ...] = ()
    label: str = ""
    help: str = ""

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            msg = f"unknown parameter kind {self.kind!r} for {self.name!r}"
            raise ValueError(msg)
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            msg = f"minimum {self.minimum} exceeds maximum {self.maximum} for {self.name!r}"
            raise ValueError(msg)

    def coerce(self, raw: str | int | float | bool) -> int | float | bool | str:
        """Convert and validate one submitted value."""
        if self.kind == "bool":
            return _coerce_bool(self.name, raw)
        if self.kind == "enum":
            return _coerce_enum(self.name, raw, self.choices)
        if self.kind == "int":
            return _coerce_number(self.name, raw, integer=True, low=self.minimum, high=self.maximum)
        return _coerce_number(self.name, raw, integer=False, low=self.minimum, high=self.maximum)


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """One built-in rule the owner can configure."""

    id: str
    name: str
    description: str
    detector: str
    params: tuple[ParamSpec, ...] = ()
    default_enabled: bool = True

    def param(self, name: str) -> ParamSpec | None:
        """Return the spec for ``name``, or ``None``."""
        return next((spec for spec in self.params if spec.name == name), None)

    def defaults(self) -> dict[str, int | float | bool | str]:
        """The shipped default for each parameter."""
        values: dict[str, int | float | bool | str] = {}
        for spec in self.params:
            values[spec.name] = spec.default
        return values


class RuleCatalogue:
    """The immutable set of configurable rules."""

    def __init__(self, definitions: Iterable[RuleDefinition]) -> None:
        self._definitions = list(definitions)
        seen: set[str] = set()
        for definition in self._definitions:
            if definition.id in seen:
                msg = f"duplicate rule id {definition.id!r}"
                raise ValueError(msg)
            seen.add(definition.id)
        self._by_id = {definition.id: definition for definition in self._definitions}

    def definitions(self) -> list[RuleDefinition]:
        return list(self._definitions)

    def get(self, rule_id: str) -> RuleDefinition | None:
        return self._by_id.get(rule_id)

    def require(self, rule_id: str) -> RuleDefinition:
        definition = self._by_id.get(rule_id)
        if definition is None:
            msg = f"unknown rule {rule_id!r}"
            raise RuleParamError(msg)
        return definition

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._by_id


@dataclass(frozen=True, slots=True)
class RuleSetting:
    """A rule's current state: enabled, plus its effective parameters."""

    rule_id: str
    enabled: bool
    params: dict[str, int | float | bool | str] = field(
        default_factory=lambda: dict[str, int | float | bool | str]()
    )


@dataclass(frozen=True, slots=True)
class Suppression:
    """One allowlist entry: silence events from this source for this rule."""

    id: int
    rule_id: str
    field: SuppressionField
    value: str
    note: str = ""
    created_ts: float = 0.0


def default_catalogue() -> RuleCatalogue:
    """The built-in rule catalogue, mirroring the shipped detector defaults."""
    return RuleCatalogue(
        [
            RuleDefinition(
                id="arp.gateway_mac_changed",
                name="Gateway MAC changed",
                description="The gateway IP is being advertised from an unfamiliar MAC.",
                detector="arp",
            ),
            RuleDefinition(
                id="arp.ip_mac_conflict",
                name="IP/MAC conflict",
                description="An address already bound to one MAC is claimed by another.",
                detector="arp",
            ),
            RuleDefinition(
                id="arp.gratuitous_flood",
                name="Gratuitous ARP flood",
                description="Repeated gratuitous announcements, the shape of cache poisoning.",
                detector="arp",
                params=(
                    ParamSpec(
                        name="burst_threshold",
                        kind="int",
                        default=20,
                        minimum=5,
                        maximum=200,
                        label="Announcements",
                        help="Gratuitous ARPs needed inside the window.",
                    ),
                    ParamSpec(
                        name="window",
                        kind="float",
                        default=10.0,
                        minimum=1.0,
                        maximum=120.0,
                        label="Window (s)",
                    ),
                ),
            ),
            RuleDefinition(
                id="dns.spoofing",
                name="DNS spoofing",
                description="Forged, conflicting, or untrusted-resolver DNS answers.",
                detector="dns",
                params=(
                    ParamSpec(
                        name="conflicting_answers",
                        kind="bool",
                        default=True,
                        label="Report conflicting answers",
                    ),
                    ParamSpec(
                        name="conflict_threshold",
                        kind="int",
                        default=3,
                        minimum=2,
                        maximum=20,
                        label="Conflicting answer sets",
                        help="Raise this if your resolver is round-robin.",
                    ),
                    ParamSpec(
                        name="no_match_window",
                        kind="float",
                        default=2.0,
                        minimum=0.5,
                        maximum=10.0,
                        label="Query window (s)",
                    ),
                    ParamSpec(
                        name="sensitivity",
                        kind="enum",
                        default="balanced",
                        choices=("relaxed", "balanced", "strict"),
                        label="Sensitivity",
                    ),
                ),
            ),
            RuleDefinition(
                id="dhcp.rogue_server",
                name="Rogue DHCP server",
                description="A DHCP server answers on a network that has another.",
                detector="dhcp",
            ),
            RuleDefinition(
                id="dhcp.config_drift",
                name="DHCP configuration drift",
                description="A trusted server offers a different gateway or resolver.",
                detector="dhcp",
            ),
            RuleDefinition(
                id="dhcp.starvation",
                name="DHCP starvation",
                description="DISCOVER flooding or a mass probe from many clients.",
                detector="dhcp",
                params=(
                    ParamSpec(
                        name="discover_threshold",
                        kind="int",
                        default=50,
                        minimum=5,
                        maximum=1000,
                        label="DISCOVERs per window",
                    ),
                    ParamSpec(
                        name="distinct_clients",
                        kind="int",
                        default=100,
                        minimum=5,
                        maximum=2000,
                        label="Distinct clients",
                    ),
                    ParamSpec(
                        name="window",
                        kind="float",
                        default=10.0,
                        minimum=1.0,
                        maximum=120.0,
                        label="Window (s)",
                    ),
                ),
            ),
            RuleDefinition(
                id="scan.vertical",
                name="Vertical port scan",
                description="One source probing many ports on a host.",
                detector="scan_flood",
                params=(
                    ParamSpec(
                        name="port_threshold",
                        kind="int",
                        default=20,
                        minimum=5,
                        maximum=200,
                        label="Ports per source",
                    ),
                    ParamSpec(
                        name="scan_window",
                        kind="float",
                        default=10.0,
                        minimum=1.0,
                        maximum=300.0,
                        label="Window (s)",
                    ),
                ),
            ),
            RuleDefinition(
                id="scan.horizontal",
                name="Horizontal port scan",
                description="One source probing many hosts.",
                detector="scan_flood",
                params=(
                    ParamSpec(
                        name="host_threshold",
                        kind="int",
                        default=20,
                        minimum=5,
                        maximum=200,
                        label="Hosts per source",
                    ),
                    ParamSpec(
                        name="scan_window",
                        kind="float",
                        default=10.0,
                        minimum=1.0,
                        maximum=300.0,
                        label="Window (s)",
                    ),
                ),
            ),
            RuleDefinition(
                id="scan.syn_flood",
                name="SYN flood",
                description="SYN volume high enough to exhaust a server's connection table.",
                detector="scan_flood",
                params=(
                    ParamSpec(
                        name="syn_threshold",
                        kind="int",
                        default=100,
                        minimum=10,
                        maximum=10000,
                        label="SYNs per target",
                    ),
                    ParamSpec(
                        name="syn_window",
                        kind="float",
                        default=1.0,
                        minimum=0.1,
                        maximum=60.0,
                        label="Window (s)",
                    ),
                ),
            ),
            RuleDefinition(
                id="inventory.new_device",
                name="New device",
                description="Report devices that have never been seen before.",
                detector="inventory",
                params=(
                    ParamSpec(
                        name="learning_seconds",
                        kind="int",
                        default=600,
                        minimum=0,
                        maximum=86400,
                        label="Learning period (s)",
                        help="Devices seen during this window are absorbed silently.",
                    ),
                ),
            ),
            RuleDefinition(
                id="suricata.alerts",
                name="Suricata signature alerts",
                description="Import alerts from the Suricata engine.",
                detector="suricata",
                params=(
                    ParamSpec(
                        name="min_severity",
                        kind="enum",
                        default="medium",
                        choices=("info", "low", "medium", "high", "critical"),
                        label="Minimum severity",
                    ),
                ),
            ),
        ]
    )


def _coerce_bool(name: str, raw: str | int | float | bool) -> bool:
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    msg = f"{name} must be a boolean, got {raw!r}"
    raise RuleParamError(msg)


def _coerce_enum(name: str, raw: str | int | float | bool, choices: Sequence[str]) -> str:
    text = str(raw).strip().lower()
    if text not in choices:
        msg = f"{name} must be one of {', '.join(choices)}; got {raw!r}"
        raise RuleParamError(msg)
    return text


def _coerce_number(
    name: str,
    raw: str | int | float | bool,
    *,
    integer: bool,
    low: float | None,
    high: float | None,
) -> int | float:
    text = str(raw).strip()
    try:
        value: int | float = int(text) if integer else float(text)
    except ValueError as exc:
        msg = f"{name} must be a number, got {raw!r}"
        raise RuleParamError(msg) from exc
    if low is not None and value < low:
        msg = f"{name} must be at least {low:g}, got {value:g}"
        raise RuleParamError(msg)
    if high is not None and value > high:
        msg = f"{name} must be at most {high:g}, got {value:g}"
        raise RuleParamError(msg)
    return value


def _normalise_suppression(field_: SuppressionField, value: str) -> str:
    """Normalise an allowlist value, rejecting anything malformed.

    MACs and IP addresses are canonicalised so that ``DE-AD-BE-EF-00-01`` and
    ``de:ad:be:ef:00:01`` are the same entry. Everything else is stored literally —
    patterns are never compiled, so ``.*`` matches only the literal string ``.*``.
    """
    text = value.strip()
    if not text:
        msg = "suppression value cannot be empty"
        raise RuleParamError(msg)
    if field_ is SuppressionField.SRC_MAC:
        try:
            return normalize_mac(text)
        except ValueError as exc:
            msg = f"not a MAC address: {value!r}"
            raise RuleParamError(msg) from exc
    if field_ in (SuppressionField.SRC_IP, SuppressionField.DST_IP):
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            msg = f"not an IP address: {value!r}"
            raise RuleParamError(msg) from exc
    return text


_SCHEMA = """
CREATE TABLE IF NOT EXISTS rule_settings (
    rule_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL,
    params  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS suppressions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id    TEXT NOT NULL,
    field      TEXT NOT NULL,
    value      TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_suppressions_rule ON suppressions(rule_id);
"""

_RULE_TYPES: dict[str, EventType] = {
    "arp.gateway_mac_changed": EventType.ARP_SPOOF,
    "arp.ip_mac_conflict": EventType.ARP_SPOOF,
    "arp.gratuitous_flood": EventType.ARP_SPOOF,
    "dns.spoofing": EventType.DNS_SPOOF,
    "dhcp.rogue_server": EventType.DHCP_ROGUE,
    "dhcp.config_drift": EventType.DHCP_ROGUE,
    "dhcp.starvation": EventType.DHCP_ROGUE,
    "scan.vertical": EventType.PORT_SCAN,
    "scan.horizontal": EventType.PORT_SCAN,
    "scan.syn_flood": EventType.SYN_FLOOD,
    "inventory.new_device": EventType.NEW_DEVICE,
    "suricata.alerts": EventType.SURICATA_ALERT,
}

#: Which rule produced an event, keyed by the ``details["reason"]`` the detectors set.
#: Two ARP checks (unsolicited replies, Ethernet source mismatch) deliberately have no
#: v1 rule of their own; they are absent here and therefore never gated.
_REASON_RULES: dict[str, str] = {
    "gateway_mac_changed": "arp.gateway_mac_changed",
    "ip_mac_conflict": "arp.ip_mac_conflict",
    "gratuitous_arp_flood": "arp.gratuitous_flood",
    "rogue_dhcp_server": "dhcp.rogue_server",
    "dhcp_config_drift": "dhcp.config_drift",
    "dhcp_starvation": "dhcp.starvation",
    "vertical_port_scan": "scan.vertical",
    "horizontal_port_scan": "scan.horizontal",
    "syn_flood": "scan.syn_flood",
    "new_device": "inventory.new_device",
    "response_without_matching_query": "dns.spoofing",
    "untrusted_resolver": "dns.spoofing",
    "conflicting_answers": "dns.spoofing",
}


def rule_id_for_event(event: Event) -> str | None:
    """The catalogue rule that produced ``event``, when it can be told.

    Every detector labels its output with a ``reason``; that label is the precise link
    back to the rule the owner toggled. Suricata alerts carry a signature id instead,
    and resolve by event type. Events whose rule cannot be told return ``None`` and are
    never gated by rule settings.
    """
    reason = str(event.details.get("reason", ""))
    known = _REASON_RULES.get(reason)
    if known is not None:
        return known
    if event.type is EventType.SURICATA_ALERT:
        return "suricata.alerts"
    return None


def suppression_applies(suppression: Suppression, event: Event) -> bool:
    """Whether one allowlist entry silences ``event``.

    Scope matters: when the event's originating rule is known, only that rule's
    entries may match — an allowlist entry for ``arp.gateway_mac_changed`` must not
    silence an IP/MAC conflict from the same detector. Events whose rule cannot be
    told fall back to matching any rule sharing their event type, which keeps
    hand-built events (and tests) working.
    """
    event_rule = rule_id_for_event(event)
    if event_rule is not None:
        if suppression.rule_id != event_rule:
            return False
    elif _RULE_TYPES.get(suppression.rule_id) is not event.type:
        return False
    return _suppression_matches_value(suppression, event)


def _suppression_matches_value(suppression: Suppression, event: Event) -> bool:
    if suppression.field is SuppressionField.ANY:
        return True
    actual = getattr(event, str(suppression.field), None)
    if actual is None:
        return False
    if suppression.field is SuppressionField.SRC_MAC:
        try:
            return normalize_mac(str(actual)) == suppression.value
        except ValueError:
            return False
    return str(actual) == suppression.value


class RuleConfigService:
    """Reads and writes rule settings and allowlists, validated against the catalogue."""

    def __init__(self, database: Database, catalogue: RuleCatalogue) -> None:
        self._db = database
        self.catalogue = catalogue
        self._db.executescript(_SCHEMA)

    # --- settings ---------------------------------------------------------

    def settings(self) -> dict[str, RuleSetting]:
        """Every rule's current state, defaults filled in for unset rules.

        A row whose stored JSON cannot be read (hand-edited file, interrupted write,
        schema from a future version) falls back to that rule's defaults instead of
        raising: the Rules page must stay loadable and the sensor must stay startable.
        """
        stored: dict[str, tuple[bool, dict[str, int | float | bool | str]]] = {}
        for row in self._db.query("SELECT rule_id, enabled, params FROM rule_settings"):
            rule_id = str(row["rule_id"])
            try:
                raw = json.loads(row["params"])
            except ValueError:
                logger.warning("ignoring unreadable parameters for rule %s", rule_id)
                raw = {}
            if not isinstance(raw, dict):
                logger.warning("ignoring non-object parameters for rule %s", rule_id)
                raw = {}
            params: dict[str, int | float | bool | str] = {}
            for key, value in cast("dict[object, object]", raw).items():
                if isinstance(key, str) and isinstance(value, (int, float, bool, str)):
                    params[key] = value
                else:
                    logger.warning("ignoring unusable parameter %r for rule %s", key, rule_id)
            stored[rule_id] = (bool(row["enabled"]), params)
        result: dict[str, RuleSetting] = {}
        for definition in self.catalogue.definitions():
            enabled, params = stored.get(definition.id, (definition.default_enabled, {}))
            merged: dict[str, int | float | bool | str] = definition.defaults()
            merged.update(params)
            result[definition.id] = RuleSetting(
                rule_id=definition.id, enabled=enabled, params=merged
            )
        return result

    def set_enabled(self, rule_id: str, enabled: bool) -> RuleSetting:
        """Enable or disable one rule."""
        self.catalogue.require(rule_id)
        current = self.settings()[rule_id]
        self._store(rule_id, enabled, current.params)
        return self.settings()[rule_id]

    def set_params(self, rule_id: str, params: Mapping[str, object]) -> RuleSetting:
        """Validate and store typed parameters for one rule.

        Nothing is written unless *every* value validates, so a partially-valid form
        never leaves a rule half-configured.
        """
        definition = self.catalogue.require(rule_id)
        current = self.settings()[rule_id]
        merged = dict(current.params)

        for name, raw in params.items():
            spec = definition.param(name)
            if spec is None:
                msg = f"rule {rule_id!r} has no parameter {name!r}"
                raise RuleParamError(msg)
            merged[name] = spec.coerce(raw)  # type: ignore[arg-type]

        self._store(rule_id, current.enabled, merged)
        return self.settings()[rule_id]

    def effective_params(self, rule_id: str) -> dict[str, int | float | bool | str]:
        """The parameters to hand to a detector when it is built."""
        self.catalogue.require(rule_id)
        return dict(self.settings()[rule_id].params)

    def _store(self, rule_id: str, enabled: bool, params: Mapping[str, object]) -> None:
        self._db.execute(
            "INSERT INTO rule_settings (rule_id, enabled, params) VALUES (?, ?, ?) "
            "ON CONFLICT(rule_id) DO UPDATE SET "
            "enabled = excluded.enabled, params = excluded.params",
            (rule_id, 1 if enabled else 0, json.dumps(params, sort_keys=True)),
        )

    # --- allowlists -------------------------------------------------------

    def suppressions(self) -> list[Suppression]:
        """Every allowlist entry, newest first."""
        return [
            Suppression(
                id=int(row["id"]),
                rule_id=str(row["rule_id"]),
                field=SuppressionField(row["field"]),
                value=str(row["value"]),
                note=str(row["note"]),
                created_ts=float(row["created_ts"]),
            )
            for row in self._db.query("SELECT * FROM suppressions ORDER BY id DESC")
        ]

    def add_suppression(
        self, rule_id: str, field_: SuppressionField, value: str, note: str = ""
    ) -> Suppression:
        """Add an allowlist entry after validating the value."""
        self.catalogue.require(rule_id)
        normalised = _normalise_suppression(field_, value)
        created = time.time()
        cursor = self._db.execute(
            "INSERT INTO suppressions (rule_id, field, value, note, created_ts) "
            "VALUES (?, ?, ?, ?, ?)",
            (rule_id, str(field_), normalised, note.strip()[:200], created),
        )
        return Suppression(
            id=int(cursor.lastrowid or 0),
            rule_id=rule_id,
            field=field_,
            value=normalised,
            note=note.strip()[:200],
            created_ts=created,
        )

    def remove_suppression(self, suppression_id: int) -> None:
        """Delete an allowlist entry."""
        cursor = self._db.execute("DELETE FROM suppressions WHERE id = ?", (suppression_id,))
        if cursor.rowcount == 0:
            msg = f"unknown suppression {suppression_id}"
            raise RuleParamError(msg)

    def is_suppressed(self, event: Event) -> bool:
        """Whether an event is silenced by the allowlist."""
        return any(suppression_applies(suppression, event) for suppression in self.suppressions())
