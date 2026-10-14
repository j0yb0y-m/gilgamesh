"""New / unknown device detector (catalogue item #5).

**What it is for.** An unfamiliar machine on the home network is the cheapest early
warning available: a compromised IoT bulb, a neighbour's laptop on an open port, or a
stranger plugging into the hallway socket. Seeing it *first* is what makes the other
alerts meaningful — an ARP alert from an unknown MAC is far worse than one from the TV.

**Why this is ours.** Neither Suricata nor a signature rule has any concept of "a
device". This module keeps the inventory itself and is also the source the Devices page
and the allowlists read from.

**Detection logic.** The first time a MAC address is seen (after a learning period) one
informational/low ``new_device`` event is emitted, carrying the addresses and, where
known, a hostname or vendor. Repeat sightings update ``first_seen``/``last_seen`` and
never re-alert, so a device that is simply online does not spam the owner.

**False positives — this detector is dominated by MAC randomisation.** iOS, Android,
Windows and most modern TVs derive a *locally administered* MAC per network, so the same
phone presents a different address every time it joins. Treating each as a new device
would make the feature worthless within a day. Four guards follow:

* The **locally administered bit** (the low bit of the first octet, per IEEE 802) marks a
  randomised address. Such devices are reported ``info`` and labelled
  *"likely randomised device"* rather than ``medium`` *"unknown device"*.
* **Trusted** devices — the owner's own kit, and anything confirmed in the UI — never
  alert at all.
* A **learning period** at start-up absorbs the storm when the bridge comes up and every
  device announces itself at once.
* **Coalescing is per MAC**, and the event pipeline adds dedup/cooldown on top.

**Known limitations.** MAC randomisation defeats per-device identity on modern phones;
tracking by DHCP hostname or IPv6 address would be the next step. Guests are genuinely
new devices and cannot be told apart from an intruder. Vendor lookup from the OUI is not
implemented (it would mean shipping an OUI database and a licence review), so
``vendor`` stays empty.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.base import Detector
from gilgamesh.util.net import IPV4_ZERO, normalize_mac

#: I/G (individual/group) bit of the first octet. Set = locally administered, i.e. a
#: randomised address rather than one burned into the hardware (IEEE 802 addressing).
_LOCAL_ADMIN_BIT = 0x02


def is_randomised_mac(mac: str) -> bool:
    """Return whether ``mac`` is locally administered, i.e. likely randomised.

    Callers are expected to pass an already-normalised address; malformed input is
    treated as not randomised rather than raising, because a bad address should not
    stop the sensor.
    """
    try:
        first_octet = int(normalize_mac(mac).split(":")[0], 16)
    except ValueError:
        return False
    return bool(first_octet & _LOCAL_ADMIN_BIT)


class Device(BaseModel):
    """One device in the inventory."""

    model_config = ConfigDict(frozen=True)

    mac: str
    ips: tuple[str, ...] = ()
    hostname: str | None = None
    vendor: str | None = None
    first_seen: float
    last_seen: float
    trusted: bool = False
    randomised: bool = False
    label: str | None = None


@dataclass(frozen=True, slots=True)
class InventoryConfig:
    """Tunable behaviour for the inventory."""

    #: Absorb the start-up storm of every device announcing itself at once.
    learning_seconds: float = 600.0
    #: Cap on remembered devices, so a spoofed source sweep cannot exhaust memory.
    max_devices: int = 512
    interface: str | None = None


@dataclass(frozen=True, slots=True)
class ObservedDevice:
    """What a single packet told us about a device."""

    mac: str
    ip: str | None
    hostname: str | None


@dataclass(slots=True)
class _DeviceState:
    """Mutable bookkeeping for one device while it is being observed."""

    ips: set[str] = field(default_factory=lambda: set[str]())
    hostname: str | None = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    trusted: bool = False
    randomised: bool = False
    label: str | None = None

    def to_model(self, mac: str) -> Device:
        return Device(
            mac=mac,
            ips=tuple(sorted(self.ips)),
            hostname=self.hostname,
            vendor=None,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            trusted=self.trusted,
            randomised=self.randomised,
            label=self.label,
        )


def observe_device(packet: object) -> ObservedDevice | None:
    """Return the device identity a packet reveals, or ``None``.

    The Ethernet source address is authoritative even when the packet carries a
    spoofed IP header, so it is used for identity and the IP is recorded separately.
    """
    if not isinstance(packet, Packet):
        return None
    if Ether not in packet:
        return None

    try:
        mac = normalize_mac(str(packet[Ether].src))
    except ValueError:
        return None

    ip: str | None = None
    hostname: str | None = None
    if IP in packet:
        ip = str(packet[IP].src)
    elif ARP in packet:
        # ARP carries the sender's protocol address outright, and is often the only
        # place a device states it: an ARP announcement has no IP header at all.
        candidate = str(packet[ARP].psrc)
        ip = candidate if candidate != IPV4_ZERO else None

    return ObservedDevice(mac=mac, ip=ip, hostname=hostname)


class InventoryDetector(Detector):
    """Tracks devices and reports the first sighting of each one."""

    name = "inventory"

    def __init__(self, config: InventoryConfig, clock: Callable[[], float] | None = None) -> None:
        self._config = config
        self._clock = clock if clock is not None else time.monotonic
        self._started_at = self._clock()
        self._devices: OrderedDict[str, _DeviceState] = OrderedDict()
        self._pending: list[Event] = []

    @property
    def device_count(self) -> int:
        """Number of devices currently in the inventory."""
        return len(self._devices)

    def events(self) -> list[Event]:
        """Return and clear the events produced by the most recent packet."""
        pending = self._pending
        self._pending = []
        return pending

    def device(self, mac: str) -> Device | None:
        """Return one device by MAC address, or ``None`` if it is unknown."""
        state = self._devices.get(self._key(mac))
        if state is None:
            return None
        return state.to_model(self._key(mac))

    def mark_trusted(self, mac: str, name: str | None = None) -> None:
        """Trust a device so it stops being reported, optionally giving it a name."""
        key = self._key(mac)
        state = self._devices.setdefault(key, _DeviceState())
        state.trusted = True
        if name is not None:
            state.label = name

    def process(self, packet: object) -> list[Event]:
        """Inspect one captured packet and return the events it triggered."""
        observed = observe_device(packet)
        if observed is None:
            return []

        now = self._clock()
        was_known = self._remember(observed, now)

        events: list[Event] = []
        if not was_known and not self._in_learning(now):
            events.append(self._new_device_event(observed))

        self._pending = events
        return events

    def _remember(self, observed: ObservedDevice, now: float) -> bool:
        """Record this sighting. Returns ``True`` if the device was already known."""
        key = observed.mac
        state = self._devices.get(key)
        if state is None:
            state = _DeviceState(
                first_seen=now,
                last_seen=now,
                randomised=is_randomised_mac(key),
            )
            self._devices[key] = state
            while len(self._devices) > self._config.max_devices:
                self._devices.popitem(last=False)
            is_new = True
        else:
            self._devices.move_to_end(key)
            state.last_seen = now
            is_new = False

        if observed.ip:
            state.ips.add(observed.ip)
        if observed.hostname:
            state.hostname = observed.hostname
        return not is_new

    def _in_learning(self, now: float) -> bool:
        """Whether we are still absorbing the start-up announcement storm."""
        return now - self._started_at < self._config.learning_seconds

    def _new_device_event(self, observed: ObservedDevice) -> Event:
        """Build the one-off event announcing a device we have never seen."""
        state = self._devices[observed.mac]

        if state.randomised:
            summary = (
                f"New randomised device at {observed.mac} — likely a phone or laptop "
                "using a per-network address"
            )
        else:
            summary = f"New device {observed.mac} seen on the network"

        details: dict[str, object] = {
            "reason": "new_device",
            "mac": observed.mac,
            "ips": sorted(state.ips),
            "randomised": state.randomised,
        }
        if state.trusted:
            details["trusted"] = True

        return Event(
            type=EventType.NEW_DEVICE,
            # A randomised address is far more likely to be the owner's own phone.
            severity=Severity.INFO if state.randomised else Severity.LOW,
            detector=self.name,
            summary=summary,
            src_mac=observed.mac,
            src_ip=observed.ip,
            interface=self._config.interface,
            details=details,
        )

    @staticmethod
    def _key(mac: str) -> str:
        """Normalise a MAC for use as a dictionary key, falling back to the raw value."""
        try:
            return normalize_mac(mac)
        except ValueError:
            return mac.strip().lower()
