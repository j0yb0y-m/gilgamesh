"""M6 — port scan and SYN flood detector tests.

Scanning is the noisiest thing on any network: the public internet scans a home
connection constantly, and a single inbound SYN is identical whether it is a scanner or
a browser. The detector therefore has to separate *shape* (one source touching many
ports or many hosts in a burst, without completing handshakes) from *volume*, and it
must never confuse a busy-but-legitimate session for a scan.
"""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.scan_flood import ScanConfig, ScanDetector

CLIENT = "10.0.0.2"
SERVER = "10.0.0.5"
ATTACKER = "203.0.113.9"
VERTICAL_THRESHOLD = 20
HORIZONTAL_THRESHOLD = 20


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self._now = 5000.0

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def syn(src: str, dst: str, sport: int, dport: int) -> Packet:
    """A bare SYN, the first packet of a connection attempt or a scan."""
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")


def syn_ack(src: str, dst: str, sport: int, dport: int) -> Packet:
    """The server's half-open reply, which proves the port accepted a handshake."""
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="SA")


def make_detector(**overrides: float) -> tuple[ScanDetector, FakeClock]:
    """Build a detector, defaulting the thresholds to the shipped values."""
    clock = FakeClock()
    config = ScanConfig(
        vertical_threshold=VERTICAL_THRESHOLD,
        horizontal_threshold=HORIZONTAL_THRESHOLD,
        **overrides,  # type: ignore[arg-type]
    )
    return ScanDetector(config, clock=clock.now), clock


def complete_handshake(detector: ScanDetector, server_port: int, sport: int = 40000) -> list[Event]:
    """Run one full TCP connection: SYN, SYN-ACK, ACK, then close."""
    detector.process(syn(CLIENT, SERVER, sport, server_port))
    detector.process(syn_ack(SERVER, CLIENT, server_port, sport))
    detector.process(IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=server_port, flags="A"))
    detector.process(IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=server_port, flags="F"))
    return detector.process(
        IP(src=SERVER, dst=CLIENT) / TCP(sport=sport, dport=server_port, flags="A")
    )


def test_vertical_scan_is_detected() -> None:
    detector, _ = make_detector()
    events: list[Event] = []
    for offset in range(VERTICAL_THRESHOLD + 1):
        events.extend(detector.process(syn(CLIENT, SERVER, 40000 + offset, 1000 + offset)))

    assert len(events) == 1
    assert events[0].type is EventType.PORT_SCAN
    assert events[0].severity is Severity.MEDIUM
    assert events[0].details["reason"] == "vertical_port_scan"
    assert events[0].details["distinct_ports"] == VERTICAL_THRESHOLD + 1
    assert events[0].src_ip == CLIENT


def test_horizontal_scan_is_detected() -> None:
    detector, _ = make_detector()
    events: list[Event] = []
    for offset in range(HORIZONTAL_THRESHOLD + 1):
        host = f"10.0.1.{offset}"
        events.extend(detector.process(syn(CLIENT, host, 40000 + offset, 443)))

    assert len(events) == 1
    assert events[0].details["reason"] == "horizontal_port_scan"
    assert events[0].details["distinct_hosts"] == HORIZONTAL_THRESHOLD + 1


def test_completed_connections_are_not_a_scan() -> None:
    """Benign and critical: an app opening many ports, each fully handshaked."""
    detector, clock = make_detector()
    events: list[Event] = []

    for index in range(VERTICAL_THRESHOLD + 5):
        events.extend(complete_handshake(detector, server_port=1000 + index, sport=40000 + index))
        clock.advance(0.5)

    assert events == []


def test_bulk_transfer_on_one_port_is_not_a_scan() -> None:
    """Benign: a download is thousands of packets, but all on one already-open port."""
    detector, _ = make_detector()
    complete_handshake(detector, server_port=443)

    events: list[Event] = []
    for offset in range(200):
        events.extend(
            detector.process(
                IP(src=SERVER, dst=CLIENT) / TCP(sport=443, dport=40000, flags="A") / b"x" * 64
            )
        )
        del offset

    assert events == []


def test_normal_browsing_does_not_alert() -> None:
    detector, clock = make_detector()
    events: list[Event] = []
    for index in range(8):
        events.extend(complete_handshake(detector, server_port=443, sport=41000 + index))
        clock.advance(2.0)

    assert events == []


def test_syn_flood_against_one_host_is_detected() -> None:
    detector, _ = make_detector(syn_flood_threshold=100, syn_flood_window=1.0)
    events: list[Event] = []

    for offset in range(101):
        events.extend(detector.process(syn(ATTACKER, SERVER, 30000 + offset, 80)))

    floods = [event for event in events if event.details.get("reason") == "syn_flood"]
    assert len(floods) == 1
    assert floods[0].type is EventType.SYN_FLOOD
    assert floods[0].severity is Severity.HIGH
    assert floods[0].dst_ip == SERVER
    assert floods[0].details["syn_count"] == 101


def test_syn_flood_window_expires() -> None:
    detector, clock = make_detector(syn_flood_threshold=50, syn_flood_window=1.0)
    for offset in range(60):
        detector.process(syn(ATTACKER, SERVER, 30000 + offset, 80))
    clock.advance(5.0)

    assert detector.process(syn(ATTACKER, SERVER, 31000, 80)) == []


def test_global_syn_threshold_is_applied() -> None:
    """A flood spread over many destinations still has a shape."""
    detector, _ = make_detector(home_syn_threshold=100, syn_flood_threshold=1000)
    events: list[Event] = []

    for offset in range(120):
        host = f"10.0.{offset // 200}.{offset % 200 + 1}"
        events.extend(detector.process(syn(ATTACKER, host, 30000 + offset, 80)))

    assert any(event.details.get("reason") == "syn_flood" for event in events)


def test_scan_window_expires() -> None:
    detector, clock = make_detector()
    for offset in range(VERTICAL_THRESHOLD + 1):
        detector.process(syn(CLIENT, SERVER, 40000 + offset, 1000 + offset))
    clock.advance(60.0)

    assert detector.process(syn(CLIENT, SERVER, 41000, 2000)) == []


def test_established_flows_are_remembered_only_within_the_window() -> None:
    detector, clock = make_detector()
    complete_handshake(detector, server_port=443)
    clock.advance(600.0)

    for offset in range(VERTICAL_THRESHOLD + 1):
        detector.process(syn(CLIENT, SERVER, 42000 + offset, 3000 + offset))

    events = detector.process(syn(CLIENT, SERVER, 43000, 3100))
    assert [event.details["reason"] for event in events] == ["vertical_port_scan"]


def test_non_tcp_traffic_is_ignored() -> None:
    detector, _ = make_detector()
    packet = IP(src=CLIENT, dst=SERVER) / UDP(sport=1234, dport=53)

    assert detector.process(packet) == []


def test_tracked_sources_are_bounded() -> None:
    detector, _ = make_detector(max_tracked_sources=32)
    for offset in range(500):
        detector.process(syn(f"10.9.{offset // 250}.{offset % 250 + 1}", SERVER, 40000, 80))

    assert detector.tracked_source_count <= 32


def test_events_drains_the_most_recent_detection() -> None:
    detector, _ = make_detector()
    for offset in range(VERTICAL_THRESHOLD + 1):
        detector.process(syn(CLIENT, SERVER, 40000 + offset, 1000 + offset))

    assert len(detector.events()) == 1
    assert detector.events() == []
