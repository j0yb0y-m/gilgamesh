"""ARP spoofing / poisoning detector (catalogue item #1).

**The attack.** ARP (RFC 826) has no authentication. A machine on the local network can
send an unsolicited ARP reply claiming that the gateway's IP address lives at *its* MAC.
Every host that trusts the reply then sends its traffic — including DNS queries and
passwords — to the attacker instead of the gateway. The same trick in the other
direction lets an attacker poison a victim's cache so the victim's replies are diverted.
Because ARP is broadcast and unverified, this is the cheapest attack on a home network
and needs no special position on the LAN.

**Why this is ours and not Suricata's.** Suricata 8.0.7 has an ARP *decoder and logger*
but no ARP rule keyword — it cannot alert on ARP at all. More fundamentally, detecting
poisoning needs a *baseline* (who owns which IP, and which MAC is the real gateway),
and baselines are state Gilgamesh has to keep itself.

**Detection logic.** The detector maintains a table of learned IP→MAC bindings and
recognises five shapes of poisoning:

1. ``gateway_mac_changed`` — the gateway IP is announced from a MAC we have not seen
   there before. The strongest signal available, so it alerts immediately.
2. ``ip_mac_conflict`` — an IP already bound to one MAC is claimed by another: two
   devices fighting over one address.
3. ``ethernet_source_mismatch`` — the Ethernet header's source MAC differs from the MAC
   inside the ARP payload, which is how proxy/offload paths and spoofing tools differ.
4. ``unsolicited_arp_reply`` — a reply that matches no recent request *and* disagrees
   with what we have already learned.
5. ``gratuitous_arp_flood`` — more than ``garp_burst_threshold`` gratuitous announcements
   for one address inside ``garp_window_seconds``.

**False positives — this is the hard part of ARP detection, and the reason the
thresholds are deliberately conservative.** A home network is not quiet:

* **DHCP lease handover / renewals** legitimately change an IP→MAC binding.
* **Wi-Fi roaming, mesh nodes, and repeaters** re-announce addresses for devices behind
  them, and a mesh AP is often the only MAC the rest of the LAN ever sees.
* **RFC 5227 gratuitous ARPs** fire at every interface-up and during ARP self-test. They
  are normal, so a single gratuitous ARP is never an alert — only a flood is.
* **ARP probes** (sender address all-zero, or ``0.0.0.0``) are a device checking whether
  an address is free. They are ignored entirely.
* **Proxy ARP** (one router answering on behalf of many hosts) makes Ethernet and ARP
  source addresses differ by design.
* **Failover / virtual MACs** (VMs, Wi-Fi powersave) move addresses between MACs.

Three guards follow from this. A **warm-up** period learns the network before judging
it. A reply that **agrees with a binding we already learned** is treated as a
re-announcement, not an attack. And the *event pipeline* (dedup, cooldown, aggregation)
collapses the repeated announcements a single poisoning attempt produces.

**Known limitation.** With no prior knowledge, the first ARP seen for an IP is learned
as truth, so an attacker already on the network when Gilgamesh boots could poison the
gateway binding during warm-up. Learning the gateway's MAC from DHCP rather than from
the wire would close this and is the natural next step.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from scapy.layers.l2 import ARP, Ether

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.base import PacketDetector
from gilgamesh.util.net import IPV4_ZERO, MAC_ZERO, normalize_mac

ARP_REQUEST = 1
ARP_REPLY = 2


@dataclass(frozen=True, slots=True)
class ArpConfig:
    """Tunable thresholds. Defaults are proposals to be tuned on real traffic."""

    #: The home gateway's address. When ``None`` the gateway-specific check is skipped
    #: (the sensor could not find the default route); every other check still runs.
    gateway_ip: str | None = None
    #: Learned bindings are collected but not judged for this long after start-up.
    warmup_seconds: float = 300.0
    #: How long a request stays "answered", before a reply to it looks unsolicited.
    request_ttl_seconds: float = 5.0
    #: Gratuitous ARPs from one MAC needed inside the window to count as a flood.
    garp_burst_threshold: int = 20
    garp_window_seconds: float = 10.0
    #: Recorded on emitted events; the capture layer knows the real interface.
    interface: str | None = None


@dataclass(frozen=True, slots=True)
class ArpPacket:
    """The fields of an ARP frame this detector cares about."""

    op: int
    eth_src: str
    eth_dst: str
    hwsrc: str
    psrc: str
    hwdst: str
    pdst: str

    @property
    def is_probe(self) -> bool:
        """An ARP probe: a sender still checking whether an address is free."""
        return self.hwsrc == MAC_ZERO or self.psrc == IPV4_ZERO

    @property
    def is_gratuitous(self) -> bool:
        """A gratuitous ARP (RFC 5227): the sender and target protocol address match."""
        return self.psrc == self.pdst


def parse_arp(packet: object) -> ArpPacket | None:
    """Return the ARP fields of ``packet``, or ``None`` if it is not an ARP frame.

    Returns ``None`` (rather than raising) for non-ARP traffic, because a capture
    stream is mostly not ARP and malformed addresses must not stop the sensor.
    """
    if not isinstance(packet, Ether) or ARP not in packet:
        return None
    ethernet = packet[Ether]
    arp = packet[ARP]
    try:
        return ArpPacket(
            op=int(arp.op),
            eth_src=normalize_mac(str(ethernet.src)),
            eth_dst=normalize_mac(str(ethernet.dst)),
            hwsrc=normalize_mac(str(arp.hwsrc)),
            psrc=str(arp.psrc),
            hwdst=normalize_mac(str(arp.hwdst)),
            pdst=str(arp.pdst),
        )
    except ValueError:
        return None


class ArpDetector(PacketDetector):
    """Detects ARP poisoning by correlating ARP frames against learned bindings."""

    name = "arp"

    def __init__(self, config: ArpConfig, clock: Callable[[], float] | None = None) -> None:
        self._config = config
        self._clock = clock if clock is not None else time.monotonic
        self._started_at = self._clock()
        self._bindings: dict[str, set[str]] = {}
        self._gateway_mac: str | None = None
        self._requests: dict[str, float] = {}
        self._garp: dict[str, deque[float]] = {}
        self._pending: list[Event] = []

    @property
    def bindings(self) -> dict[str, set[str]]:
        """Learned IP→MAC bindings. Exposed for the device inventory."""
        return self._bindings

    def events(self) -> list[Event]:
        """Return and clear the events produced by the most recent packet."""
        pending = self._pending
        self._pending = []
        return pending

    def process(self, packet: object) -> list[Event]:
        """Inspect one captured packet and return the events it triggered."""
        frame = parse_arp(packet)
        if frame is None or frame.is_probe:
            return []

        now = self._clock()
        warming_up = now - self._started_at < self._config.warmup_seconds

        if frame.op == ARP_REQUEST:
            self._note_request(frame, now)

        events: list[Event] = []
        events.extend(self._check_gateway_mac(frame, warming_up))
        events.extend(self._check_ip_mac_conflict(frame, warming_up))
        events.extend(self._check_ethernet_source(frame, warming_up))
        events.extend(self._check_unsolicited_reply(frame, now, warming_up))
        events.extend(self._check_gratuitous_flood(frame, now, warming_up))

        self._learn(frame)
        self._pending = events
        return events

    def _note_request(self, frame: ArpPacket, now: float) -> None:
        """Record "``hwsrc`` just asked who has ``pdst``" for unsolicited-reply checks."""
        ttl = self._config.request_ttl_seconds
        stale = [key for key, seen in self._requests.items() if now - seen >= ttl]
        for key in stale:
            del self._requests[key]
        self._requests[f"{frame.pdst}|{frame.hwsrc}"] = now

    def _check_gateway_mac(self, frame: ArpPacket, warming_up: bool) -> list[Event]:
        """Alert when the gateway IP is claimed from a MAC other than the learned one."""
        if self._config.gateway_ip is None or frame.psrc != self._config.gateway_ip:
            return []
        known = self._gateway_mac
        if known is None:
            self._gateway_mac = frame.hwsrc
            return []
        if known == frame.hwsrc or warming_up:
            return []
        return [
            self._event(
                severity=Severity.HIGH,
                reason="gateway_mac_changed",
                src_mac=frame.hwsrc,
                src_ip=frame.psrc,
                summary=(
                    f"Gateway {frame.psrc} is being advertised as {frame.hwsrc} "
                    f"(expected {known}) — possible ARP spoofing"
                ),
                details={"previous_mac": known, "claimed_mac": frame.hwsrc, "ip": frame.psrc},
            )
        ]

    def _check_ip_mac_conflict(self, frame: ArpPacket, warming_up: bool) -> list[Event]:
        """Alert when an IP already bound to one MAC is claimed by a different one.

        The gateway IP is excluded: a changed gateway MAC is reported by
        :meth:`_check_gateway_mac`, which carries better evidence.
        """
        if self._config.gateway_ip is not None and frame.psrc == self._config.gateway_ip:
            return []
        known = self._bindings.get(frame.psrc)
        if known is None or frame.hwsrc in known:
            return []
        previous = sorted(known)[0]
        if warming_up:
            return []
        return [
            self._event(
                severity=Severity.HIGH,
                reason="ip_mac_conflict",
                src_mac=frame.hwsrc,
                src_ip=frame.psrc,
                summary=(
                    f"{frame.psrc} is claimed by {frame.hwsrc} but was seen at {previous} "
                    "— possible ARP spoofing"
                ),
                details={"ip": frame.psrc, "known_mac": previous, "claimed_mac": frame.hwsrc},
            )
        ]

    def _check_ethernet_source(self, frame: ArpPacket, warming_up: bool) -> list[Event]:
        """Alert when the Ethernet and ARP sender addresses disagree.

        Note this is also what proxy ARP looks like, which is why it is ``medium``
        rather than ``high`` and why a real-network tuning pass may be needed.
        """
        if frame.eth_src == frame.hwsrc or warming_up:
            return []
        return [
            self._event(
                severity=Severity.MEDIUM,
                reason="ethernet_source_mismatch",
                src_mac=frame.eth_src,
                src_ip=frame.psrc,
                summary=(f"Ethernet source {frame.eth_src} differs from ARP sender {frame.hwsrc}"),
                details={
                    "ethernet_src": frame.eth_src,
                    "arp_source": frame.hwsrc,
                    "ip": frame.psrc,
                },
            )
        ]

    def _check_unsolicited_reply(
        self, frame: ArpPacket, now: float, warming_up: bool
    ) -> list[Event]:
        """Alert on a reply that answers no request and disagrees with what we learned."""
        if frame.op != ARP_REPLY or frame.is_gratuitous:
            return []
        asked_at = self._requests.get(f"{frame.psrc}|{frame.hwdst}")
        if asked_at is not None and now - asked_at < self._config.request_ttl_seconds:
            return []
        if frame.hwsrc in self._bindings.get(frame.psrc, set()):
            return []
        if warming_up:
            return []
        return [
            self._event(
                severity=Severity.MEDIUM,
                reason="unsolicited_arp_reply",
                src_mac=frame.hwsrc,
                src_ip=frame.psrc,
                summary=f"Unsolicited ARP reply claiming {frame.psrc} is at {frame.hwsrc}",
                details={"ip": frame.psrc, "claimed_mac": frame.hwsrc, "target": frame.hwdst},
            )
        ]

    def _check_gratuitous_flood(
        self, frame: ArpPacket, now: float, warming_up: bool
    ) -> list[Event]:
        """Alert on a burst of gratuitous announcements for one address.

        Individual gratuitous ARPs are normal (RFC 5227); a burst from one MAC is the
        shape of a poisoning attempt trying to overwrite many caches at once.
        """
        if not frame.is_gratuitous:
            return []
        hits = self._garp.setdefault(frame.hwsrc, deque[float]())
        window = self._config.garp_window_seconds
        while hits and now - hits[0] >= window:
            hits.popleft()
        hits.append(now)
        threshold = self._config.garp_burst_threshold
        if len(hits) <= threshold or warming_up:
            return []
        return [
            self._event(
                severity=Severity.HIGH,
                reason="gratuitous_arp_flood",
                src_mac=frame.hwsrc,
                src_ip=frame.psrc,
                summary=(
                    f"{len(hits)} gratuitous ARP announcements for {frame.psrc} "
                    f"from {frame.hwsrc} within {window:g}s"
                ),
                details={
                    "ip": frame.psrc,
                    "claimed_mac": frame.hwsrc,
                    "count": len(hits),
                    "window_seconds": window,
                },
            )
        ]

    def _learn(self, frame: ArpPacket) -> None:
        """Record the binding this frame asserts."""
        self._bindings.setdefault(frame.psrc, set()).add(frame.hwsrc)

    def _event(
        self,
        *,
        severity: Severity,
        reason: str,
        src_mac: str | None,
        src_ip: str | None,
        summary: str,
        details: dict[str, object],
    ) -> Event:
        return Event(
            type=EventType.ARP_SPOOF,
            severity=severity,
            detector=self.name,
            summary=summary,
            src_mac=src_mac,
            src_ip=src_ip,
            interface=self._config.interface,
            details={"reason": reason, **details},
        )
