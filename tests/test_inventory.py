"""M7 — new/unknown device detector tests.

An unfamiliar machine on a home network is the single most common early warning: it is
usually a compromised IoT device, a guest who borrowed a socket, or someone else's phone.
It is also the easiest thing to get wrong, because modern phones, laptops and TVs
routinely present **different MAC addresses on every network they join**. Treating each
of those as a new device would make the alert meaningless within a day.
"""

from __future__ import annotations

from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from gilgamesh.models import EventType, Severity
from gilgamesh.sensors.inventory import InventoryConfig, InventoryDetector

# A globally-unique unicast MAC has bits 0 (multicast) and 1 (locally administered)
# both clear in the first octet, so the low octets below start with 0x00.
KNOWN_MAC = "00:11:22:33:44:02"
NEW_MAC = "00:11:22:33:44:99"
RANDOMISED_MAC = "8a:1f:3c:4d:5e:6f"  # 0x8a -> locally administered bit set
KNOWN_IP = "10.0.0.2"
NEW_IP = "10.0.0.55"


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self._now = 9000.0

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def arp_from(mac: str, ip: str) -> Packet:
    """A device announcing itself over ARP, which is how the inventory learns it."""
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst="10.0.0.1"
    )


def ip_traffic(mac: str, src_ip: str, dst_ip: str = "10.0.0.1") -> Packet:
    """Ordinary IP traffic, used to learn a device that never sends ARP.

    Note the parentheses: ``pkt / b"x" * 20`` would parse as ``(pkt / b"x") * 20``
    and silently produce a list of twenty packets.
    """
    return Ether(src=mac, dst="00:11:22:33:44:55") / IP(src=src_ip, dst=dst_ip) / (b"\x00" * 20)


def make_detector(
    *, learning_seconds: float = 0.0, max_devices: int = 512
) -> tuple[InventoryDetector, FakeClock]:
    """Build a detector with learning disabled unless a test asks for it."""
    clock = FakeClock()
    config = InventoryConfig(learning_seconds=learning_seconds, max_devices=max_devices)
    return InventoryDetector(config, clock=clock.now), clock


def test_first_sighting_emits_a_new_device_event() -> None:
    detector, _ = make_detector()

    events = detector.process(arp_from(NEW_MAC, NEW_IP))

    assert len(events) == 1
    assert events[0].type is EventType.NEW_DEVICE
    assert events[0].severity is Severity.LOW
    assert events[0].details["reason"] == "new_device"
    assert events[0].details["mac"] == NEW_MAC
    assert events[0].details["randomised"] is False


def test_known_device_is_not_reported_again() -> None:
    detector, clock = make_detector()
    detector.process(arp_from(KNOWN_MAC, KNOWN_IP))

    for _ in range(20):
        assert detector.process(arp_from(KNOWN_MAC, KNOWN_IP)) == []
        clock.advance(1.0)


def test_randomised_mac_is_labelled_and_downgraded() -> None:
    """The locally-administered bit marks a randomised address — worth saying out loud."""
    detector, _ = make_detector()

    events = detector.process(arp_from(RANDOMISED_MAC, "10.0.0.77"))

    assert events[0].details["randomised"] is True
    assert events[0].severity is Severity.INFO
    assert "randomised" in events[0].summary


def test_learning_period_absorbs_existing_devices() -> None:
    detector, clock = make_detector(learning_seconds=600.0)

    assert detector.process(arp_from(KNOWN_MAC, KNOWN_IP)) == []
    clock.advance(700.0)
    # A device that already existed during learning is never "new" afterwards.
    assert detector.process(arp_from(KNOWN_MAC, KNOWN_IP)) == []
    # A device that genuinely appears after learning is reported.
    assert detector.process(arp_from(NEW_MAC, NEW_IP)) != []


def test_trusted_devices_are_never_reported() -> None:
    detector, _ = make_detector()
    detector.mark_trusted(KNOWN_MAC, name="Living-room TV")

    assert detector.process(arp_from(KNOWN_MAC, KNOWN_IP)) == []


def test_device_is_tracked_with_its_addresses() -> None:
    detector, clock = make_detector()
    detector.process(arp_from(KNOWN_MAC, KNOWN_IP))
    clock.advance(1.0)
    detector.process(ip_traffic(KNOWN_MAC, "10.0.0.8"))

    device = detector.device(KNOWN_MAC)

    assert device is not None
    assert device.mac == KNOWN_MAC
    assert set(device.ips) == {KNOWN_IP, "10.0.0.8"}
    assert device.trusted is False


def test_first_and_last_seen_are_recorded() -> None:
    detector, clock = make_detector()
    detector.process(arp_from(KNOWN_MAC, KNOWN_IP))
    clock.advance(120.0)
    detector.process(arp_from(KNOWN_MAC, KNOWN_IP))

    device = detector.device(KNOWN_MAC)

    assert device is not None
    assert device.last_seen - device.first_seen == 120.0


def test_inventory_is_bounded() -> None:
    detector, _ = make_detector(max_devices=16)
    for index in range(200):
        mac = f"00:11:22:33:{index // 250:02x}:{index % 250 + 1:02x}"
        detector.process(ip_traffic(mac, f"10.5.{index // 250}.{index % 250 + 1}"))

    assert detector.device_count <= 16


def test_oversized_inventory_evicts_least_recently_seen() -> None:
    detector, clock = make_detector(max_devices=4)
    for index in range(4):
        detector.process(ip_traffic(f"00:11:22:33:44:{index:02x}", f"10.6.0.{index}"))
        clock.advance(1.0)

    detector.process(ip_traffic("00:11:22:33:44:ff", "10.6.0.254"))

    assert detector.device("00:11:22:33:44:00") is None
    assert detector.device("00:11:22:33:44:ff") is not None


def test_non_ethernet_traffic_is_ignored() -> None:
    detector, _ = make_detector()
    assert detector.process(IP(src=NEW_IP, dst="10.0.0.1") / (b"\x00" * 20)) == []


def test_events_drains_the_most_recent_detection() -> None:
    detector, _ = make_detector()
    detector.process(arp_from(NEW_MAC, NEW_IP))

    assert len(detector.events()) == 1
    assert detector.events() == []
