"""M3 — ARP spoofing / poisoning detector tests.

Every detector in Gilgamesh has two obligations (constraint C10 and the project's own
rule): a test that the **attack** is caught, and a test that **benign traffic** does
not trip it. Home networks are noisy — DHCP lease handovers, Wi-Fi roaming, mesh
repeaters and RFC 5227 gratuitous ARPs at interface-up all look superficially like
poisoning — so the negative tests matter as much as the positive ones.
"""

from __future__ import annotations

from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from gilgamesh.models import EventType, Severity
from gilgamesh.sensors.arp import ArpConfig, ArpDetector
from gilgamesh.util.net import IPV4_ZERO, MAC_ZERO

GATEWAY_IP = "10.0.0.1"
GATEWAY_MAC = "aa:bb:cc:00:00:01"
ATTACKER_MAC = "de:ad:be:ef:00:01"
HOST_MAC = "aa:bb:cc:00:00:02"
HOST_IP = "10.0.0.2"


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self._now = 1000.0

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def arp_request(
    src_mac: str, src_ip: str, dst_mac: str = MAC_ZERO, dst_ip: str = GATEWAY_IP
) -> Packet:
    """Build a broadcast ARP request (who has ``dst_ip``?)."""
    return Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip
    )


def arp_reply(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> Packet:
    """Build a unicast ARP reply (``src_ip`` is at ``src_mac``)."""
    return Ether(src=src_mac, dst=dst_mac) / ARP(
        op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip
    )


def gratuitous_arp(mac: str, ip: str, op: int = 2) -> Packet:
    """Build an RFC 5227 gratuitous ARP announcement (``psrc == pdst``)."""
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=op, hwsrc=mac, psrc=ip, hwdst=MAC_ZERO, pdst=ip
    )


def make_detector(
    *,
    warmup_seconds: float = 0.0,
    request_ttl_seconds: float = 5.0,
    garp_burst_threshold: int = 20,
    garp_window_seconds: float = 10.0,
) -> tuple[ArpDetector, FakeClock]:
    """Build a detector with warm-up disabled unless a test asks for it."""
    clock = FakeClock()
    config = ArpConfig(
        gateway_ip=GATEWAY_IP,
        warmup_seconds=warmup_seconds,
        request_ttl_seconds=request_ttl_seconds,
        garp_burst_threshold=garp_burst_threshold,
        garp_window_seconds=garp_window_seconds,
    )
    return ArpDetector(config, clock=clock.now), clock


def learn_gateway(detector: ArpDetector) -> None:
    """Teach the detector the real gateway's MAC, as a healthy network would."""
    detector.process(arp_request(HOST_MAC, HOST_IP))
    detector.process(arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP))


def test_gateway_mac_change_is_detected() -> None:
    detector, _ = make_detector()
    learn_gateway(detector)

    events = detector.process(arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP))

    assert len(events) == 1
    assert events[0].type is EventType.ARP_SPOOF
    assert events[0].severity is Severity.HIGH
    assert events[0].details["previous_mac"] == GATEWAY_MAC
    assert events[0].details["claimed_mac"] == ATTACKER_MAC
    assert events[0].dedup_key.startswith("arp|")


def test_repeated_gateway_traffic_does_not_alert() -> None:
    """The common case: a normal host talking to the real gateway must be silent."""
    detector, clock = make_detector()
    learn_gateway(detector)

    for _ in range(20):
        assert detector.process(arp_request(HOST_MAC, HOST_IP)) == []
        clock.advance(1.0)
        assert detector.process(arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)) == []


def test_two_macs_claiming_one_ip_is_detected() -> None:
    detector, _ = make_detector()
    detector.process(arp_request(HOST_MAC, HOST_IP))

    events = detector.process(arp_request(ATTACKER_MAC, HOST_IP))

    assert len(events) == 1
    assert events[0].details["ip"] == HOST_IP
    assert events[0].details["known_mac"] == HOST_MAC
    assert events[0].details["claimed_mac"] == ATTACKER_MAC


def test_device_reannouncing_itself_does_not_alert() -> None:
    """Benign: a host re-advertising its own IP/MAC pair (the DHCP-renewal shape)."""
    detector, clock = make_detector()
    detector.process(arp_request(HOST_MAC, HOST_IP))

    for _ in range(10):
        assert detector.process(arp_reply(HOST_MAC, HOST_IP, GATEWAY_MAC, GATEWAY_IP)) == []
        clock.advance(0.5)


def test_arp_probe_is_ignored() -> None:
    """A sender still probing for a free address uses an all-zero sender address."""
    detector, _ = make_detector()
    probe = Ether(src=MAC_ZERO, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=MAC_ZERO, psrc=IPV4_ZERO, hwdst=MAC_ZERO, pdst=HOST_IP
    )

    assert detector.process(probe) == []


def test_unsolicited_arp_reply_is_detected() -> None:
    detector, _ = make_detector()

    events = detector.process(arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP))

    assert [event.details["reason"] for event in events] == ["unsolicited_arp_reply"]


def test_reply_to_a_seen_request_is_not_flagged() -> None:
    detector, clock = make_detector()

    detector.process(arp_request(HOST_MAC, HOST_IP))
    clock.advance(0.1)

    assert detector.process(arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)) == []


def test_stale_request_leads_to_unsolicited_reply() -> None:
    """Once the original request ages out, a later reply is genuinely unsolicited."""
    detector, clock = make_detector(request_ttl_seconds=5.0)
    detector.process(arp_request(HOST_MAC, HOST_IP))
    clock.advance(30.0)

    events = detector.process(arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP))

    assert [event.details["reason"] for event in events] == ["unsolicited_arp_reply"]


def test_single_gratuitous_arp_does_not_alert() -> None:
    """RFC 5227 gratuitous ARPs are normal at interface-up and must not be flagged."""
    detector, clock = make_detector()
    learn_gateway(detector)

    for _ in range(5):
        assert detector.process(gratuitous_arp(GATEWAY_MAC, GATEWAY_IP)) == []
        clock.advance(1.0)


def test_gratuitous_arp_flood_is_detected() -> None:
    detector, clock = make_detector(garp_burst_threshold=20, garp_window_seconds=10.0)
    learn_gateway(detector)

    for _ in range(25):
        detector.process(gratuitous_arp(ATTACKER_MAC, GATEWAY_IP))
        clock.advance(0.2)

    # Inside the 10 s window the flood is detected once it exceeds the threshold.
    floods = detector.process(gratuitous_arp(ATTACKER_MAC, GATEWAY_IP))

    assert any(event.details.get("reason") == "gratuitous_arp_flood" for event in floods)


def test_ethernet_source_mismatch_is_detected() -> None:
    detector, _ = make_detector()
    packet = Ether(src=HOST_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=ATTACKER_MAC, psrc=HOST_IP, hwdst="00:00:00:00:00:00", pdst=GATEWAY_IP
    )

    events = detector.process(packet)

    assert [event.details["reason"] for event in events] == ["ethernet_source_mismatch"]


def test_warmup_learns_without_alerting() -> None:
    detector, clock = make_detector(warmup_seconds=300.0)
    detector.process(arp_request(HOST_MAC, HOST_IP))

    clock.advance(10.0)
    assert detector.process(arp_request(ATTACKER_MAC, HOST_IP)) == []


def test_non_arp_traffic_is_ignored() -> None:
    detector, _ = make_detector()

    assert detector.process(Ether(src=HOST_MAC, dst=GATEWAY_MAC) / b"\x08\x00payload") == []


def test_events_drains_the_most_recent_detection() -> None:
    """The Detector contract: ``events()`` yields what the last packet produced."""
    detector, _ = make_detector()

    detector.process(arp_request(HOST_MAC, HOST_IP))
    detector.process(arp_request(ATTACKER_MAC, HOST_IP))

    pending = detector.events()

    assert len(pending) == 1
    assert detector.events() == []
