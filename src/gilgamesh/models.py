"""Normalized event model shared by every detector.

Every detector — custom Scapy/AF_PACKET modules and the Suricata EVE tailer alike —
emits :class:`Event` objects into the same pipeline (decision D-004). Keeping one
shape means deduplication, storage, and notification never need to know which
detector produced an alert.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field


class EventType(StrEnum):
    """Category of a detected event.

    ``TEST`` exists so the walking skeleton can prove the pipeline end to end
    without pretending to detect anything real.
    """

    TEST = "test"
    ARP_SPOOF = "arp_spoof"
    DNS_SPOOF = "dns_spoof"
    DHCP_ROGUE = "dhcp_rogue"
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    NEW_DEVICE = "new_device"
    SURICATA_ALERT = "suricata_alert"


class Severity(StrEnum):
    """How serious an event is. Ordered via :attr:`Severity.rank`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Return the ordinal used for comparisons and thresholds."""
        return _SEVERITY_ORDER.index(self)

    def escalated(self) -> Severity:
        """Return the next-higher severity, capped at :attr:`CRITICAL`.

        Used when an incident keeps repeating: a burst that was merely ``medium``
        becomes ``high`` once the volume shows the attack is sustained.
        """
        return _SEVERITY_ORDER[min(self.rank + 1, len(_SEVERITY_ORDER) - 1)]


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


class Event(BaseModel):
    """One normalized detector event.

    Attributes mirror the schema in ``docs/PLAN.md`` §6. Instances are immutable so
    an event cannot be mutated between the sensor writing it and the web process
    reading it.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    type: EventType
    severity: Severity
    detector: str
    summary: str
    src_mac: str | None = None
    src_ip: str | None = None
    dst_mac: str | None = None
    dst_ip: str | None = None
    interface: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    incident_id: int | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dedup_key(self) -> str:
        """Stable key identifying "the same attack" for dedup and aggregation.

        Two events with the same key describe the same attack seen repeatedly
        (e.g. a gateway claiming a new MAC every few seconds) and must collapse
        into one incident instead of producing one alert per packet.
        """
        return "|".join((self.detector, str(self.type), self.src_ip or "-", self.dst_ip or "-"))
