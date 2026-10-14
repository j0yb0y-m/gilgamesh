"""Port scan and SYN flood detector (catalogue item #4).

**The attack.** A port scan walks a host (vertical) or a subnet (horizontal) to build a
map of what is listening. A SYN flood aims to exhaust a server's half-open connection
table so real users are refused service. On a home network the practical targets are a
NAS, a camera, a router's admin interface, or a laptop running a development server —
and a compromised IoT device scanning the LAN is the usual first step of a larger attack.

**Why this is ours and not Suricata's.** Suricata 8 has no ``sfPortscan`` equivalent:
the available tools are ``threshold``, ``detection_filter`` and ``rate_filter`` applied
to *per-packet* rules, which cannot see "one source touching 25 ports in 10 seconds".
That is a correlation over time, which is what this module maintains. Suricata's ET
``emerging-scan`` and ``emerging-dos`` rules add signatures on top, but the home-network
tuning is ours.

**Detection logic.**

1. ``vertical_port_scan`` — one source opening more than ``vertical_threshold`` distinct
   **destination ports** inside ``scan_window``. ``MEDIUM``.
2. ``horizontal_port_scan`` — one source reaching more than ``horizontal_threshold``
   distinct **destination hosts** inside the window. ``MEDIUM``.
3. ``syn_flood`` — more than ``syn_flood_threshold`` SYNs to a *single* destination
   inside ``syn_flood_window``, or more than ``home_syn_threshold`` SYNs from one source
   across all destinations. ``HIGH``.

**False positives — and this is the hard part, because the internet scans us constantly.**
A public IP receives background SYN scans from the whole internet; alerting on each one
would make the tool useless. Therefore:

* **A completed handshake exonerates the port.** The decisive signal separating a scanner
  from a busy application is that a scanner's probes do not complete. Once a SYN-ACK is
  seen for ``(source, host, port)`` that combination is removed from the scan counters
  and stays removed for the window. An application opening 25 ports sequentially passes
  through this unharmed, because each handshake completes before the next SYN arrives.
* **Volume alone is never a scan.** A download is thousands of packets on one already
  established port; that never touches the distinct-port or distinct-host counters.
* **Counters are windowed**, so a burst ages out instead of poisoning the state forever.

**Known limitations.** Without payload inspection this cannot distinguish a scan from a
port-knocking or service-discovery tool that completes its handshakes. NAT means every
device behind one router shares an address, which dilutes per-source counts (and can make
a LAN-wide scan look like one source). Encrypted traffic is opaque, and IPv6 counting is
deferred to v1.1 (D-026).
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.base import Detector

_FIN = 0x01
_SYN = 0x02
_ACK = 0x10


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Tunable thresholds. Defaults are proposals to be tuned on real traffic."""

    #: Distinct destination ports from one source that constitute a vertical scan.
    vertical_threshold: int = 20
    #: Distinct destination hosts from one source that constitute a horizontal scan.
    horizontal_threshold: int = 20
    #: Sliding window for the scan counters.
    scan_window: float = 10.0
    #: SYNs to a single destination inside ``syn_flood_window`` that constitute a flood.
    syn_flood_threshold: int = 100
    syn_flood_window: float = 1.0
    #: SYNs from one source across all destinations that constitute a flood.
    home_syn_threshold: int = 1000
    #: How long a completed handshake exonerates a port.
    established_ttl: float = 60.0
    #: Memory bounds, so a spoofed source sweep cannot exhaust the Pi.
    max_tracked_sources: int = 2048
    max_tracked_flows: int = 8192
    interface: str | None = None


@dataclass(frozen=True, slots=True)
class TcpFrame:
    """The TCP/IP fields this detector uses."""

    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    flags: int

    @property
    def is_syn(self) -> bool:
        """A bare SYN: the opening packet of a connection or a probe."""
        return bool(self.flags & _SYN) and not bool(self.flags & _ACK)

    @property
    def is_syn_ack(self) -> bool:
        """The server's reply, proving this flow completed a handshake."""
        return bool(self.flags & _SYN) and bool(self.flags & _ACK)

    @property
    def is_fin(self) -> bool:
        return bool(self.flags & _FIN)


def parse_tcp(packet: object) -> TcpFrame | None:
    """Return the TCP/IP content of ``packet``, or ``None`` if it is not TCP."""
    if not isinstance(packet, Packet):
        return None
    if IP not in packet or TCP not in packet:
        return None
    ip = packet[IP]
    tcp = packet[TCP]
    return TcpFrame(
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        sport=int(tcp.sport),
        dport=int(tcp.dport),
        flags=int(tcp.flags),
    )


@dataclass(slots=True)
class _SourceState:
    """Recent activity attributed to one source address."""

    ports: dict[int, float] = field(default_factory=lambda: dict[int, float]())
    hosts: dict[str, float] = field(default_factory=lambda: dict[str, float]())
    syns: deque[float] = field(default_factory=lambda: deque[float]())


class ScanDetector(Detector):
    """Detects vertical/horizontal port scans and SYN floods."""

    name = "scan_flood"

    def __init__(self, config: ScanConfig, clock: Callable[[], float] | None = None) -> None:
        self._config = config
        self._clock = clock if clock is not None else time.monotonic
        self._sources: OrderedDict[str, _SourceState] = OrderedDict()
        self._established: OrderedDict[tuple[str, str, int], float] = OrderedDict()
        self._destination_syns: dict[str, deque[float]] = {}
        self._pending: list[Event] = []

    @property
    def tracked_source_count(self) -> int:
        """Number of source addresses currently held in memory."""
        return len(self._sources)

    def events(self) -> list[Event]:
        """Return and clear the events produced by the most recent packet."""
        pending = self._pending
        self._pending = []
        return pending

    def process(self, packet: object) -> list[Event]:
        """Inspect one captured packet and return the events it triggered."""
        frame = parse_tcp(packet)
        if frame is None:
            return []

        now = self._clock()
        self._prune(now)

        events: list[Event] = []
        if frame.is_syn_ack:
            self._remember_established(frame, now)
        elif frame.is_syn:
            events.extend(self._observe_syn(frame, now))
        else:
            # Non-SYN traffic proves nothing new about scanning; keep state LRU-fresh.
            self._touch(frame.src_ip)

        self._pending = events
        return events

    def _observe_syn(self, frame: TcpFrame, now: float) -> list[Event]:
        """Record a SYN and judge it against the scan and flood thresholds."""
        state = self._state_for(frame.src_ip)

        if not self._is_established(frame):
            state.ports.setdefault(frame.dport, now)
            state.hosts.setdefault(frame.dst_ip, now)
        state.syns.append(now)

        syns = self._destination_syns.setdefault(frame.dst_ip, deque[float]())
        window = self._config.syn_flood_window
        while syns and now - syns[0] >= window:
            syns.popleft()
        syns.append(now)

        events: list[Event] = []
        events.extend(self._check_vertical(frame, state, now))
        events.extend(self._check_horizontal(frame, state, now))
        events.extend(self._check_flood(frame, len(syns), len(state.syns)))
        return events

    def _check_vertical(self, frame: TcpFrame, state: _SourceState, now: float) -> list[Event]:
        """Alert when one source touches too many ports without completing handshakes."""
        del now
        threshold = self._config.vertical_threshold
        counted = [
            port
            for port in state.ports
            if (frame.src_ip, frame.dst_ip, port) not in self._established
        ]
        if len(counted) <= threshold:
            return []
        return [
            self._event(
                frame,
                EventType.PORT_SCAN,
                Severity.MEDIUM,
                reason="vertical_port_scan",
                summary=(
                    f"{frame.src_ip} probed {len(counted)} ports on {frame.dst_ip} "
                    f"without completing a handshake"
                ),
                details={
                    "distinct_ports": len(counted),
                    "threshold": threshold,
                    "window_seconds": self._config.scan_window,
                    "ports": sorted(counted)[:32],
                },
            )
        ]

    def _check_horizontal(self, frame: TcpFrame, state: _SourceState, now: float) -> list[Event]:
        """Alert when one source reaches too many hosts without completing handshakes."""
        del now
        threshold = self._config.horizontal_threshold
        counted = [
            host
            for host in state.hosts
            if not any(key[0] == frame.src_ip and key[1] == host for key in self._established)
        ]
        if len(counted) <= threshold:
            return []
        return [
            self._event(
                frame,
                EventType.PORT_SCAN,
                Severity.MEDIUM,
                reason="horizontal_port_scan",
                summary=(
                    f"{frame.src_ip} probed {len(counted)} hosts on port {frame.dport} "
                    "without completing a handshake"
                ),
                details={
                    "distinct_hosts": len(counted),
                    "threshold": threshold,
                    "window_seconds": self._config.scan_window,
                },
            )
        ]

    def _check_flood(self, frame: TcpFrame, per_destination: int, per_source: int) -> list[Event]:
        """Alert on SYN volume aimed at one host, or spread across the network."""
        if per_destination > self._config.syn_flood_threshold:
            return [
                self._event(
                    frame,
                    EventType.SYN_FLOOD,
                    Severity.HIGH,
                    reason="syn_flood",
                    summary=(
                        f"{per_destination} SYNs from {frame.src_ip} to {frame.dst_ip} "
                        f"within {self._config.syn_flood_window:g}s"
                    ),
                    details={
                        "syn_count": per_destination,
                        "target": frame.dst_ip,
                        "threshold": self._config.syn_flood_threshold,
                    },
                )
            ]
        if per_source > self._config.home_syn_threshold:
            return [
                self._event(
                    frame,
                    EventType.SYN_FLOOD,
                    Severity.HIGH,
                    reason="syn_flood",
                    summary=(
                        f"{per_source} SYNs from {frame.src_ip} across the network "
                        f"within {self._config.scan_window:g}s"
                    ),
                    details={
                        "syn_count": per_source,
                        "threshold": self._config.home_syn_threshold,
                    },
                )
            ]
        return []

    def _remember_established(self, frame: TcpFrame, now: float) -> None:
        """Record that ``(client, server, port)`` completed a handshake."""
        del now
        key = (frame.dst_ip, frame.src_ip, frame.sport)
        self._established[key] = self._clock()
        self._established.move_to_end(key)
        while len(self._established) > self._config.max_tracked_flows:
            self._established.popitem(last=False)

    def _is_established(self, frame: TcpFrame) -> bool:
        return (frame.src_ip, frame.dst_ip, frame.dport) in self._established

    def _state_for(self, source: str) -> _SourceState:
        state = self._sources.get(source)
        if state is None:
            state = _SourceState()
            self._sources[source] = state
            while len(self._sources) > self._config.max_tracked_sources:
                self._sources.popitem(last=False)
        else:
            self._sources.move_to_end(source)
        return state

    def _touch(self, source: str) -> None:
        if source in self._sources:
            self._sources.move_to_end(source)

    def _prune(self, now: float) -> None:
        """Age out scan counters and completed handshakes outside their windows."""
        scan_window = self._config.scan_window
        for state in self._sources.values():
            state.ports = {
                port: seen for port, seen in state.ports.items() if now - seen < scan_window
            }
            state.hosts = {
                host: seen for host, seen in state.hosts.items() if now - seen < scan_window
            }
            while state.syns and now - state.syns[0] >= scan_window:
                state.syns.popleft()

        ttl = self._config.established_ttl
        self._established = OrderedDict(
            (key, seen) for key, seen in self._established.items() if now - seen < ttl
        )

        flood_window = self._config.syn_flood_window
        expired: list[str] = []
        for target, syns in self._destination_syns.items():
            while syns and now - syns[0] >= flood_window:
                syns.popleft()
            if not syns:
                expired.append(target)
        for target in expired:
            del self._destination_syns[target]

    def _event(
        self,
        frame: TcpFrame,
        event_type: EventType,
        severity: Severity,
        *,
        reason: str,
        summary: str,
        details: dict[str, object],
    ) -> Event:
        return Event(
            type=event_type,
            severity=severity,
            detector=self.name,
            summary=summary,
            src_ip=frame.src_ip,
            dst_ip=frame.dst_ip,
            interface=self._config.interface,
            details={"reason": reason, "src_port": frame.sport, "dst_port": frame.dport, **details},
        )
