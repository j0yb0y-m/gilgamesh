"""M5 — rogue DHCP server and DHCP starvation detector tests.

DHCP is the most dangerous thing to get wrong on a home network, in both directions:
a rogue server hands out the gateway and DNS addresses, so a machine can be steered
onto an attacker's network wholesale. The false-positive sources are also the most
numerous in the catalogue — two legitimate servers, failover pairs, mesh extenders,
travel routers, NAS boxes running ``dnsmasq``, and phones that reboot in a storm.
"""

from __future__ import annotations

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.dhcp import DhcpConfig, DhcpDetector
from gilgamesh.util.net import IPV4_ZERO

DISCOVER = 1
OFFER = 2
REQUEST = 3
ACK = 5

LEGIT_SERVER = "192.168.1.1"
ROGUE_SERVER = "192.168.1.66"
CLIENT_MAC = "aa:bb:cc:00:00:02"
CLIENT_IP = "10.0.0.2"
GATEWAY = "192.168.1.1"
RESOLVERS = ["1.1.1.1", "8.8.8.8"]


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self._now = 3000.0

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def dhcp_packet(
    client_mac: str = CLIENT_MAC,
    msg_type: int = OFFER,
    server_id: str | None = None,
    *,
    xid: int = 1,
    routers: list[str] | None = None,
    name_servers: list[str] | None = None,
) -> Packet:
    """Build a DHCP message from a client towards the server port."""
    options: list[tuple[str, object]] = [("message-type", msg_type)]
    if server_id is not None:
        options.append(("server_id", server_id))
    if routers is not None:
        options.append(("router", routers))
    if name_servers is not None:
        options.append(("name_server", name_servers))
    return (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=IPV4_ZERO, dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=client_mac, xid=xid, yiaddr=CLIENT_IP)
        / DHCP(options=options)
    )


def make_detector(
    *,
    trusted_servers: frozenset[str] = frozenset({LEGIT_SERVER}),
    warmup_seconds: float = 0.0,
    discover_rate_threshold: int = 50,
    distinct_clients_threshold: int = 100,
    starvation_window: float = 10.0,
) -> tuple[DhcpDetector, FakeClock]:
    """Build a detector with warm-up disabled unless a test asks for it."""
    clock = FakeClock()
    config = DhcpConfig(
        trusted_servers=trusted_servers,
        warmup_seconds=warmup_seconds,
        discover_rate_threshold=discover_rate_threshold,
        distinct_clients_threshold=distinct_clients_threshold,
        starvation_window=starvation_window,
    )
    return DhcpDetector(config, clock=clock.now), clock


def test_trusted_server_offer_does_not_alert() -> None:
    detector, clock = make_detector()
    detector.process(
        dhcp_packet(
            msg_type=OFFER, server_id=LEGIT_SERVER, routers=[GATEWAY], name_servers=RESOLVERS
        )
    )

    for _ in range(10):
        clock.advance(30.0)
        assert (
            detector.process(
                dhcp_packet(
                    msg_type=ACK,
                    server_id=LEGIT_SERVER,
                    routers=[GATEWAY],
                    name_servers=RESOLVERS,
                )
            )
            == []
        )


def test_rogue_server_offer_is_detected() -> None:
    detector, _ = make_detector()

    events = detector.process(
        dhcp_packet(
            msg_type=OFFER, server_id=ROGUE_SERVER, routers=[ROGUE_SERVER], name_servers=["6.6.6.6"]
        )
    )

    assert len(events) == 1
    assert events[0].type is EventType.DHCP_ROGUE
    assert events[0].severity is Severity.HIGH
    assert events[0].details["reason"] == "rogue_dhcp_server"
    assert events[0].details["server_id"] == ROGUE_SERVER


def test_rogue_server_ack_is_detected() -> None:
    detector, _ = make_detector()

    events = detector.process(dhcp_packet(msg_type=ACK, server_id=ROGUE_SERVER))

    assert [event.details["reason"] for event in events] == ["rogue_dhcp_server"]


def test_competing_servers_are_detected_without_an_allowlist() -> None:
    """Before DHCP has taught us the real server, a second server is the signal."""
    detector, clock = make_detector(trusted_servers=frozenset())
    detector.process(dhcp_packet(msg_type=OFFER, server_id=LEGIT_SERVER))

    assert detector.process(dhcp_packet(msg_type=OFFER, server_id=ROGUE_SERVER)) != []

    clock.advance(3600.0)
    assert detector.process(dhcp_packet(msg_type=OFFER, server_id="192.168.1.99")) != []


def test_a_single_learned_server_is_not_flagged() -> None:
    detector, clock = make_detector(trusted_servers=frozenset())

    for _ in range(10):
        assert detector.process(dhcp_packet(msg_type=OFFER, server_id=LEGIT_SERVER)) == []
        clock.advance(30.0)


def test_rogue_server_is_not_learned_as_trusted() -> None:
    """A rogue must not be able to poison the trust set by being seen once."""
    detector, _ = make_detector()

    detector.process(dhcp_packet(msg_type=OFFER, server_id=ROGUE_SERVER))

    assert LEGIT_SERVER in detector.trusted_servers
    assert ROGUE_SERVER not in detector.trusted_servers


def test_gateway_option_drift_is_detected() -> None:
    detector, _ = make_detector()
    detector.process(
        dhcp_packet(
            msg_type=OFFER, server_id=LEGIT_SERVER, routers=[GATEWAY], name_servers=RESOLVERS
        )
    )

    events = detector.process(
        dhcp_packet(msg_type=ACK, server_id=LEGIT_SERVER, routers=["10.0.0.1"])
    )

    assert len(events) == 1
    assert events[0].severity is Severity.MEDIUM
    assert events[0].details["reason"] == "dhcp_config_drift"
    assert events[0].details["changed"] == ["router"]
    assert events[0].details["expected"] == [GATEWAY]


def test_resolver_option_drift_is_detected() -> None:
    detector, _ = make_detector()
    detector.process(
        dhcp_packet(
            msg_type=OFFER, server_id=LEGIT_SERVER, routers=[GATEWAY], name_servers=RESOLVERS
        )
    )

    events = detector.process(
        dhcp_packet(msg_type=ACK, server_id=LEGIT_SERVER, name_servers=["6.6.6.6"])
    )

    assert [event.details["changed"] for event in events] == [["name_server"]]


def test_normal_boot_sequence_does_not_alert() -> None:
    """Benign: a handful of clients booting at once is a normal evening."""
    detector, _ = make_detector()
    events: list[Event] = []
    for index in range(10):
        events.extend(
            detector.process(
                dhcp_packet(
                    client_mac=f"aa:bb:cc:00:00:{index:02x}",
                    msg_type=OFFER,
                    server_id=LEGIT_SERVER,
                    xid=index,
                    routers=[GATEWAY],
                    name_servers=RESOLVERS,
                )
            )
        )

    assert events == []


def test_discover_flood_is_detected() -> None:
    detector, clock = make_detector(discover_rate_threshold=5, starvation_window=10.0)
    events: list[Event] = []
    for _ in range(8):
        events.extend(detector.process(dhcp_packet(msg_type=DISCOVER)))
        clock.advance(0.1)

    reasons = [event.details["reason"] for event in events]
    assert "dhcp_starvation" in reasons
    assert events[-1].severity is Severity.HIGH


def test_distinct_client_flood_is_detected() -> None:
    """Many clients asking at once smells like a starvation attempt, not a boot storm."""
    detector, _ = make_detector(
        distinct_clients_threshold=10, discover_rate_threshold=1000, starvation_window=60.0
    )
    events: list[Event] = []
    for index in range(15):
        events.extend(
            detector.process(
                dhcp_packet(client_mac=f"aa:bb:cc:00:{index:02x}:{index:02x}", msg_type=DISCOVER)
            )
        )

    assert any(event.details["reason"] == "dhcp_starvation" for event in events)


def test_discover_flood_window_expires() -> None:
    detector, clock = make_detector(discover_rate_threshold=5, starvation_window=10.0)
    for _ in range(6):
        detector.process(dhcp_packet(msg_type=DISCOVER))
        clock.advance(0.1)
    clock.advance(30.0)

    assert detector.process(dhcp_packet(msg_type=DISCOVER)) == []


def test_warmup_learns_without_alerting() -> None:
    detector, clock = make_detector(warmup_seconds=300.0)

    assert detector.process(dhcp_packet(msg_type=OFFER, server_id=ROGUE_SERVER)) == []
    clock.advance(400.0)
    assert detector.process(dhcp_packet(msg_type=OFFER, server_id=ROGUE_SERVER)) != []


def test_non_dhcp_traffic_is_ignored() -> None:
    detector, _ = make_detector()
    packet = Ether(src=CLIENT_MAC) / IP(src=CLIENT_IP, dst=GATEWAY) / UDP(sport=1234, dport=53)

    assert detector.process(packet) == []


def test_events_drains_the_most_recent_detection() -> None:
    detector, _ = make_detector()
    detector.process(dhcp_packet(msg_type=OFFER, server_id=ROGUE_SERVER))

    assert len(detector.events()) == 1
    assert detector.events() == []
