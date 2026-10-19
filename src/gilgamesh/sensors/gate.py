"""Apply the owner's rule settings, allowlists, and trust choices to detected events.

The Rules and Allowlist pages write to SQLite, but the decisions on *what to announce*
happen in the sensor process, which is where this gate sits. For every detected event
it answers one question: does the owner want to hear about this?

The rules it applies:

* a rule the owner disabled announces nothing;
* an allowlisted source is silenced for its rule only (not for unrelated rules);
* a device the owner marked trusted raises no "new device" alert;
* Suricata alerts below the configured minimum severity are dropped;
* ``dns.spoofing``'s ``conflicting_answers`` switch silences that one check.

**Why a cache.** The settings live in the shared database and the sensor sees every
packet, so querying per event would hammer the file. The gate keeps a snapshot and
re-reads it at most every ``refresh_seconds``, which is fast enough that a change on
the page takes effect while the attack is still running.

**Fail towards alerting.** If the rule book cannot be read — locked database, schema
from a newer version — the gate keeps the previous snapshot and never blocks. A
detector that has been told nothing must still protect the network.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.rules import (
    RuleConfigService,
    Suppression,
    rule_id_for_event,
    suppression_applies,
)
from gilgamesh.util.net import normalize_mac

logger = logging.getLogger(__name__)

#: How long a settings snapshot may be reused before it is re-read.
REFRESH_SECONDS = 30.0

#: Rule ids the gate knows how to filter beyond a simple on/off switch.
_DNS_RULE = "dns.spoofing"
_SURICATA_RULE = "suricata.alerts"


class RuleGate:
    """Decide whether a detected event should be announced."""

    def __init__(
        self,
        rules: RuleConfigService,
        devices: DeviceStore | None = None,
        *,
        refresh_seconds: float = REFRESH_SECONDS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._rules = rules
        self._devices = devices
        self._refresh_seconds = refresh_seconds
        self._clock = clock if clock is not None else time.monotonic
        #: ``None`` forces the first refresh on the first event.
        self._loaded_at: float | None = None
        self._enabled: dict[str, bool] = {}
        self._params: dict[str, dict[str, int | float | bool | str]] = {}
        self._suppressions: list[Suppression] = []
        self._trusted: set[str] = set()

    def refresh(self) -> None:
        """Re-read the snapshot, keeping the previous one if the read fails."""
        try:
            settings = self._rules.settings()
            enabled = {rule_id: setting.enabled for rule_id, setting in settings.items()}
            params = {rule_id: dict(setting.params) for rule_id, setting in settings.items()}
            suppressions = self._rules.suppressions()
            trusted: set[str] = set()
            if self._devices is not None:
                trusted = {record.mac for record in self._devices.list() if record.trusted}
        except Exception:
            # Nothing here may stop detection; the stale snapshot keeps working.
            logger.exception("could not read rule settings; using the previous snapshot")
            return
        self._enabled = enabled
        self._params = params
        self._suppressions = suppressions
        self._trusted = trusted
        self._loaded_at = self._clock()

    def allows(self, event: Event) -> bool:
        """Whether this event survives the owner's choices."""
        self._refresh_if_due()
        rule_id = rule_id_for_event(event)
        if rule_id is not None:
            if not self._enabled.get(rule_id, True):
                return False
            if (
                rule_id == _DNS_RULE
                and event.details.get("reason") == "conflicting_answers"
                and not self._param_enabled(rule_id, "conflicting_answers")
            ):
                return False
            if rule_id == _SURICATA_RULE:
                minimum = str(self._params.get(rule_id, {}).get("min_severity", "medium"))
                try:
                    floor = Severity(minimum)
                except ValueError:
                    floor = Severity.MEDIUM
                if event.severity.rank < floor.rank:
                    return False
        if event.type is EventType.NEW_DEVICE and event.src_mac and self._is_trusted(event.src_mac):
            return False
        return not self._is_suppressed(event)

    def _refresh_if_due(self) -> None:
        if self._loaded_at is None or self._clock() - self._loaded_at >= self._refresh_seconds:
            self.refresh()

    def _param_enabled(self, rule_id: str, name: str) -> bool:
        raw = self._params.get(rule_id, {}).get(name, True)
        if isinstance(raw, bool):
            return raw
        # Stored parameters round-trip through JSON; the UI writes real booleans, but a
        # hand-edited row must not silently flip the meaning.
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def _is_trusted(self, mac: str) -> bool:
        try:
            return normalize_mac(mac) in self._trusted
        except ValueError:
            return False

    def _is_suppressed(self, event: Event) -> bool:
        return any(suppression_applies(suppression, event) for suppression in self._suppressions)


__all__ = ["REFRESH_SECONDS", "RuleGate"]
