"""Rogue DHCP server and DHCP starvation detector (catalogue item #3).

**The attack.** A DHCP client trusts whatever server answers first: it accepts the
offered address, gateway, DNS servers, and lease time without checking who is talking.
An attacker who answers faster than the real router can steer a machine onto a network
they control — becoming its gateway *and* its resolver in one message. **DHCP
starvation** is the other half of the same idea: flooding DISCOVERs exhausts the real
server's address pool, or simply blocks clients from ever reaching it.

**Why this is ours and not Suricata's.** Suricata 8 does parse DHCP fully (its EVE
output carries the message type, client MAC, and the router/DNS option lists), but its
DHCP *rule keywords* only cover lease timers, and it has no concept of "the server this
network is supposed to use". Every decision here is a comparison against a learned
baseline, which only Gilgamesh keeps.

**Detection logic.**

1. ``rogue_dhcp_server`` — an OFFER or ACK whose ``server_id`` is not trusted. ``HIGH``.
2. ``dhcp_config_drift`` — a trusted server offering a *different* gateway or resolver
   list than the baseline learned from it. This catches a compromised or impersonated
   server that is "trusted" by address but steering traffic. ``MEDIUM``.
3. ``dhcp_starvation`` — more than ``discover_rate_threshold`` DISCOVERs inside
   ``starvation_window``, or more than ``distinct_clients_threshold`` distinct client
   MACs inside it. ``HIGH``.

**False positives — home networks have more legitimate DHCP servers than people expect.**
An ISP router *and* a mesh extender or a second access point both answer. Failover pairs
hand over mid-lease. Travel routers, hotspots, and NAS boxes running ``dnsmasq`` all
announce themselves. Phones reboot in storms after a router restart, and MAC-randomising
devices look like brand-new clients each time. Four guards follow:

* **Warm-up** learns before judging, so a reboot does not fire every rule at once.
* **A rogue is never learned as trusted** (there is an explicit test for this). Otherwise
  the attacker's first packet would authorise itself.
* **Without an explicit allowlist**, one server is simply *learned*; only a **second
  competing server** inside the confidence window is reported. The DHCP-learned
  server set is offered to the owner for confirmation in the web UI.
* Drift is only reported once a baseline exists, and only for options the message
  actually carries — many ACKs omit them entirely.

**Known limitations.** DHCP relays, DHCPv6 (ports 546/547, used by SLAAC networks) and
IPv6 RA are out of scope for v1 (deferred to v1.1 per decision D-026). An attacker who
simply answers *faster* than the real server with an otherwise plausible offer is caught
only by the rogue-server rule, not by drift.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import cast

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP
from scapy.packet import Packet

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.base import Detector
from gilgamesh.util.net import normalize_mac

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

MSG_DISCOVER = 1
MSG_OFFER = 2
MSG_ACK = 5
#: Messages that tell a client how to reach the network, and so need trusting.
_SERVER_MESSAGES = frozenset({MSG_OFFER, MSG_ACK})


@dataclass(frozen=True, slots=True)
class DhcpConfig:
    """Tunable thresholds and the trusted-server allowlist."""

    #: Servers known to be legitimate (from DHCP itself, or confirmed by the owner).
    trusted_servers: frozenset[str] = frozenset()
    #: Learn without judging for this long after start-up.
    warmup_seconds: float = 300.0
    #: DISCOVERs inside ``starvation_window`` that indicate flooding.
    discover_rate_threshold: int = 50
    #: Distinct client MACs inside the window that indicate a mass-probe.
    distinct_clients_threshold: int = 100
    starvation_window: float = 10.0
    #: Cap on remembered clients, so a scan cannot grow memory without bound.
    max_tracked_clients: int = 512
    interface: str | None = None


@dataclass(frozen=True, slots=True)
class DhcpFrame:
    """The parts of a DHCP message this detector uses."""

    msg_type: int
    client_mac: str
    server_id: str | None
    routers: tuple[str, ...]
    name_servers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DhcpBaseline:
    """What a legitimate server told us the network should look like."""

    routers: tuple[str, ...]
    name_servers: tuple[str, ...]


def _option(options: Sequence[object], key: str) -> object | None:
    """Return the value of a DHCP option, or ``None`` if absent.

    Scapy exposes options as a list of ``(name, value)`` pairs; unknown options appear
    as their numeric code with raw bytes, so only named options are consulted.
    """
    for entry in options:
        if not isinstance(entry, tuple):
            continue
        pair = cast("tuple[object, ...]", entry)
        if len(pair) == 2 and pair[0] == key:
            return pair[1]
    return None


def _as_tuple(value: object) -> tuple[str, ...]:
    """Normalise a DHCP address-list option into a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in cast("Sequence[object]", value))
    return (str(value),)


def _as_single(value: object) -> str | None:
    """Normalise a single-valued DHCP option such as ``server_id``."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        items = list(cast("Sequence[object]", value))
        return str(items[0]) if items else None
    return str(value)


def parse_dhcp(packet: object) -> DhcpFrame | None:
    """Return the DHCP content of ``packet``, or ``None`` if it is not DHCP."""
    if not isinstance(packet, Packet):
        return None
    if BOOTP not in packet or DHCP not in packet:
        return None
    if UDP in packet:
        udp = packet[UDP]
        if not {int(udp.sport), int(udp.dport)} & {DHCP_SERVER_PORT, DHCP_CLIENT_PORT}:
            return None

    bootp = packet[BOOTP]
    raw_chaddr = bootp.chaddr
    try:
        client_mac = normalize_mac(
            raw_chaddr.decode("ascii", "replace")
            if isinstance(raw_chaddr, bytes)
            else str(raw_chaddr)
        )
    except ValueError:
        return None

    options = cast("Sequence[object]", packet[DHCP].options)
    message_type = _option(options, "message-type")
    if not isinstance(message_type, int):
        return None

    return DhcpFrame(
        msg_type=message_type,
        client_mac=client_mac,
        server_id=_as_single(_option(options, "server_id")),
        routers=_as_tuple(_option(options, "router")),
        name_servers=_as_tuple(_option(options, "name_server")),
    )


class DhcpDetector(Detector):
    """Detects rogue DHCP servers, configuration drift, and starvation."""

    name = "dhcp"

    def __init__(self, config: DhcpConfig, clock: Callable[[], float] | None = None) -> None:
        self._config = config
        self._clock = clock if clock is not None else time.monotonic
        self._started_at = self._clock()
        self._trusted: set[str] = set(config.trusted_servers)
        self._baseline: DhcpBaseline | None = None
        self._discovers: deque[float] = deque()
        self._clients: dict[str, float] = {}
        self._pending: list[Event] = []

    @property
    def trusted_servers(self) -> frozenset[str]:
        """Servers currently trusted — learned from DHCP plus any configured allowlist."""
        return frozenset(self._trusted)

    def events(self) -> list[Event]:
        """Return and clear the events produced by the most recent packet."""
        pending = self._pending
        self._pending = []
        return pending

    def process(self, packet: object) -> list[Event]:
        """Inspect one captured packet and return the events it triggered."""
        frame = parse_dhcp(packet)
        if frame is None:
            return []

        now = self._clock()
        warming_up = now - self._started_at < self._config.warmup_seconds

        events: list[Event] = []
        if frame.msg_type == MSG_DISCOVER:
            events.extend(self._check_starvation(frame, now, warming_up))
        if frame.msg_type in _SERVER_MESSAGES:
            events.extend(self._check_server(frame, now, warming_up))
            events.extend(self._check_drift(frame, warming_up))

        self._pending = events
        return events

    def _check_server(self, frame: DhcpFrame, now: float, warming_up: bool) -> list[Event]:
        """Judge the server that answered, and learn it only when nothing is known yet.

        The rule is deliberately two-state. With no trusted server at all — a fresh
        install, before DHCP has taught us anything — the first server to answer is
        *learned*. Once any server is trusted, a different server answering is a rogue.
        That covers both the configured-allowlist case (pre-seeded, so any other server
        is immediately rogue) and the learning case, with no window bookkeeping.
        """
        del now  # the rule is state-based, not time-based
        server = frame.server_id
        if server is None or server in self._trusted:
            return []

        if not self._trusted:
            self._trusted.add(server)
            return []

        if warming_up:
            return []
        return [
            self._event(
                severity=Severity.HIGH,
                reason="rogue_dhcp_server",
                frame=frame,
                summary=f"DHCP server {server} answered but is not trusted",
                details={
                    "server_id": server,
                    "message_type": frame.msg_type,
                    "trusted_servers": sorted(self._trusted),
                },
            )
        ]

    def _check_drift(self, frame: DhcpFrame, warming_up: bool) -> list[Event]:
        """Compare a trusted server's offer against the baseline learned from it."""
        if frame.server_id is not None and frame.server_id not in self._trusted:
            return []

        if self._baseline is None:
            if not warming_up and (frame.routers or frame.name_servers):
                self._baseline = DhcpBaseline(
                    routers=frame.routers, name_servers=frame.name_servers
                )
            return []

        changed: list[str] = []
        expected: list[str] = []
        actual: list[str] = []
        for name, offered, learned in (
            ("router", frame.routers, self._baseline.routers),
            ("name_server", frame.name_servers, self._baseline.name_servers),
        ):
            if offered and learned and tuple(offered) != tuple(learned):
                changed.append(name)
                expected.extend(learned)
                actual.extend(offered)

        if not changed or warming_up:
            return []
        return [
            self._event(
                severity=Severity.MEDIUM,
                reason="dhcp_config_drift",
                frame=frame,
                summary=(
                    f"DHCP server {frame.server_id} offered different "
                    f"{' and '.join(changed)} than previously learned"
                ),
                details={
                    "changed": changed,
                    "expected": expected,
                    "received": actual,
                    "server_id": frame.server_id,
                },
            )
        ]

    def _check_starvation(self, frame: DhcpFrame, now: float, warming_up: bool) -> list[Event]:
        """Detect a DISCOVER flood or a mass-probe from many distinct clients."""
        window = self._config.starvation_window
        while self._discovers and now - self._discovers[0] >= window:
            self._discovers.popleft()
        self._discovers.append(now)

        self._clients = {mac: seen for mac, seen in self._clients.items() if now - seen < window}
        self._clients.setdefault(frame.client_mac, now)
        if len(self._clients) > self._config.max_tracked_clients:
            oldest = min(self._clients, key=lambda mac: self._clients[mac])
            del self._clients[oldest]

        if warming_up:
            return []

        if len(self._discovers) > self._config.discover_rate_threshold:
            return [
                self._event(
                    severity=Severity.HIGH,
                    reason="dhcp_starvation",
                    frame=frame,
                    summary=(
                        f"{len(self._discovers)} DHCP DISCOVERs from {frame.client_mac} "
                        f"within {window:g}s"
                    ),
                    details={
                        "discover_count": len(self._discovers),
                        "distinct_clients": len(self._clients),
                        "window_seconds": window,
                    },
                )
            ]

        if len(self._clients) > self._config.distinct_clients_threshold:
            return [
                self._event(
                    severity=Severity.HIGH,
                    reason="dhcp_starvation",
                    frame=frame,
                    summary=(
                        f"{len(self._clients)} distinct clients sent DHCP DISCOVERs "
                        f"within {window:g}s"
                    ),
                    details={
                        "discover_count": len(self._discovers),
                        "distinct_clients": len(self._clients),
                        "window_seconds": window,
                    },
                )
            ]
        return []

    def _event(
        self,
        *,
        severity: Severity,
        reason: str,
        frame: DhcpFrame,
        summary: str,
        details: dict[str, object],
    ) -> Event:
        return Event(
            type=EventType.DHCP_ROGUE,
            severity=severity,
            detector=self.name,
            summary=summary,
            src_mac=frame.client_mac,
            src_ip=None,
            interface=self._config.interface,
            details={"reason": reason, "client_mac": frame.client_mac, **details},
        )
