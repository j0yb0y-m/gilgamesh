"""M4 — DNS spoofing detector tests.

DNS is the most false-positive-prone detector in Gilgamesh: legitimate DNS is
*designed* to return different answers to the same question. CDNs and anycast
resolvers hand out different A records per client, round-robin DNS rotates them,
split-horizon DNS deliberately answers differently inside and outside the LAN, and
forwarders rewrite TTLs. So this module tests attack detection and benign tolerance
with equal weight.
"""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.dns import DnsConfig, DnsDetector

CLIENT_IP = "10.0.0.2"
RESOLVER_IP = "8.8.8.8"
EVIL_RESOLVER_IP = "1.2.3.4"
QNAME = "example.com"
REAL_ANSWER = "93.184.216.34"


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self._now = 2000.0

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def dns_query(
    client_ip: str, resolver_ip: str, dns_id: int, qname: str = QNAME, sport: int = 40000
) -> Packet:
    """Build a recursive DNS query."""
    return (
        IP(src=client_ip, dst=resolver_ip)
        / UDP(sport=sport, dport=53)
        / DNS(id=dns_id, rd=1, qd=DNSQR(qname=qname, qtype="A"))
    )


def dns_response(
    resolver_ip: str,
    client_ip: str,
    dns_id: int,
    answers: list[str],
    qname: str = QNAME,
    ttl: int = 300,
    aa: int = 0,
    dport: int = 40000,
) -> Packet:
    """Build a DNS response carrying ``answers`` (A records for ``qname``)."""
    return (
        IP(src=resolver_ip, dst=client_ip)
        / UDP(sport=53, dport=dport)
        / DNS(
            id=dns_id,
            qr=1,
            aa=aa,
            an=[DNSRR(rrname=qname, type="A", ttl=ttl, rdata=ip) for ip in answers],
        )
    )


def make_detector(
    *, trusted_resolvers: frozenset[str] = frozenset({RESOLVER_IP}), **kwargs: object
) -> tuple[DnsDetector, FakeClock]:
    """Build a detector; ``kwargs`` forwards to :class:`DnsConfig`."""
    clock = FakeClock()
    config = DnsConfig(trusted_resolvers=trusted_resolvers, **kwargs)  # type: ignore[arg-type]
    return DnsDetector(config, clock=clock.now), clock


def ask_and_answer(
    detector: DnsDetector, dns_id: int = 1, answer: str = REAL_ANSWER
) -> list[Event]:
    """Run one clean query/response exchange; returns the response's events."""
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, dns_id))
    return detector.process(dns_response(RESOLVER_IP, CLIENT_IP, dns_id, [answer], dport=40000))


def test_matched_response_does_not_alert() -> None:
    detector, _ = make_detector()

    assert ask_and_answer(detector) == []


def test_response_without_matching_query_is_detected() -> None:
    """A forged reply for a transaction id the client never used."""
    detector, _ = make_detector()
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, 1))

    events = detector.process(dns_response(RESOLVER_IP, CLIENT_IP, 999, ["6.6.6.6"]))

    assert len(events) == 1
    assert events[0].type is EventType.DNS_SPOOF
    assert events[0].severity is Severity.HIGH
    assert events[0].details["reason"] == "response_without_matching_query"
    assert events[0].src_ip == RESOLVER_IP
    assert events[0].dst_ip == CLIENT_IP


def test_response_with_no_query_history_does_not_alert() -> None:
    """Benign: Gilgamesh started capturing mid-session and missed the query."""
    detector, _ = make_detector()

    assert detector.process(dns_response(RESOLVER_IP, CLIENT_IP, 4242, [REAL_ANSWER])) == []


def test_stale_query_does_not_count_as_matched() -> None:
    detector, clock = make_detector(no_match_window_seconds=2.0)
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, 1))
    clock.advance(60.0)

    events = detector.process(dns_response(RESOLVER_IP, CLIENT_IP, 1, [REAL_ANSWER]))

    assert [event.details["reason"] for event in events] == ["response_without_matching_query"]


def test_response_from_untrusted_resolver_is_detected() -> None:
    detector, _ = make_detector()
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, 1))

    events = detector.process(dns_response(EVIL_RESOLVER_IP, CLIENT_IP, 1, ["6.6.6.6"]))

    assert [event.details["reason"] for event in events] == ["untrusted_resolver"]


def test_untrusted_resolver_is_not_judged_while_allowlist_is_empty() -> None:
    """Without DHCP-derived resolvers we have no baseline, so we must not accuse."""
    detector, _ = make_detector(trusted_resolvers=frozenset())
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, 1))

    assert detector.process(dns_response(EVIL_RESOLVER_IP, CLIENT_IP, 1, [REAL_ANSWER])) == []


def test_round_robin_answers_do_not_alert() -> None:
    """Benign: two rotating A records for one name is normal DNS, below threshold."""
    detector, clock = make_detector(conflict_threshold=3, conflict_window_seconds=30.0)

    for index, answer in enumerate(["1.1.1.1", "2.2.2.2"], start=1):
        detector.process(dns_query(CLIENT_IP, RESOLVER_IP, index))
        clock.advance(1.0)
        assert detector.process(dns_response(RESOLVER_IP, CLIENT_IP, index, [answer])) == []


def test_answers_differing_only_by_ttl_do_not_alert() -> None:
    """Benign: a forwarder rewriting TTLs must not look like a conflicting answer.

    Answer sets are compared on (name, type, rdata); TTL is excluded precisely so this
    case stays silent.
    """
    detector, clock = make_detector(conflict_threshold=2, conflict_window_seconds=30.0)

    for index, ttl in enumerate([300, 60], start=1):
        detector.process(dns_query(CLIENT_IP, RESOLVER_IP, index))
        clock.advance(1.0)
        events = detector.process(
            dns_response(RESOLVER_IP, CLIENT_IP, index, [REAL_ANSWER], ttl=ttl)
        )
        assert events == []


def test_conflicting_answers_are_detected() -> None:
    detector, clock = make_detector(conflict_threshold=3, conflict_window_seconds=30.0)
    events: list[Event] = []
    for index, answer in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"], start=1):
        detector.process(dns_query(CLIENT_IP, RESOLVER_IP, index))
        clock.advance(1.0)
        events = detector.process(dns_response(RESOLVER_IP, CLIENT_IP, index, [answer]))

    assert len(events) == 1
    assert events[0].severity is Severity.LOW
    assert events[0].details["reason"] == "conflicting_answers"
    assert events[0].details["qname"] == QNAME


def test_conflicting_answers_forget_old_entries() -> None:
    detector, clock = make_detector(conflict_threshold=3, conflict_window_seconds=30.0)
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, 1))
    detector.process(dns_response(RESOLVER_IP, CLIENT_IP, 1, ["1.1.1.1"]))

    clock.advance(120.0)
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, 2))
    events = detector.process(dns_response(RESOLVER_IP, CLIENT_IP, 2, ["2.2.2.2"]))

    assert events == []


def test_suspicious_ttl_is_recorded_as_evidence() -> None:
    detector, _ = make_detector()
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, 1))

    events = detector.process(dns_response(RESOLVER_IP, CLIENT_IP, 999, ["6.6.6.6"], ttl=1))

    assert events[0].details["suspicious_ttl"] is True
    assert events[0].details["min_ttl"] == 1


def test_normal_ttl_is_not_flagged() -> None:
    detector, _ = make_detector()
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, 1))

    events = detector.process(dns_response(RESOLVER_IP, CLIENT_IP, 999, ["6.6.6.6"], ttl=300))

    assert events[0].details["suspicious_ttl"] is False


def test_traffic_after_an_attack_is_not_alerted_again() -> None:
    detector, clock = make_detector()
    for index in range(10):
        detector.process(dns_query(CLIENT_IP, RESOLVER_IP, index))
        clock.advance(0.5)
        assert ask_and_answer(detector, dns_id=100 + index) == []


def test_non_dns_traffic_is_ignored() -> None:
    detector, _ = make_detector()
    packet = IP(src=CLIENT_IP, dst=RESOLVER_IP) / UDP(sport=40000, dport=53) / b"\x00\x01"

    assert detector.process(packet) == []


def test_events_drains_the_most_recent_detection() -> None:
    detector, _ = make_detector()
    detector.process(dns_query(CLIENT_IP, RESOLVER_IP, 1))
    detector.process(dns_response(RESOLVER_IP, CLIENT_IP, 999, ["6.6.6.6"]))

    assert len(detector.events()) == 1
    assert detector.events() == []
