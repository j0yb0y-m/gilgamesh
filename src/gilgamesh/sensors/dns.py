"""DNS spoofing detector (catalogue item #2).

**The attack.** DNS is unauthenticated and is the phone book of the internet. An
attacker on the LAN answers somebody's query *first*, with an address they control, so
the victim browses through the attacker. Variants include answering a transaction id the
victim never used, answering from a machine that is not the network's resolver, and
repeatedly answering the same question with different addresses to keep a victim pinned
to the wrong host.

**Why this is ours and not Suricata's.** Suricata 8 parses and logs DNS (its EVE output
carries the transaction id, the queries, and each answer's TTL), but it has no notion of
*which resolver should be answering*. Detecting spoofing means correlating a query with
its response and comparing the responder against a learned trust list — baselines only
Gilgamesh keeps. This module consumes the same transaction id Suricata reports.

**Detection logic.**

1. ``response_without_matching_query`` — a response whose transaction id never appeared
   as a query we observed. Two sub-cases, and the difference matters: if we *did* see a
   query for that transaction and it simply aged out, something is wrong; if the client
   was querying moments ago but never used this id, a response was forged. A client we
   have never seen querying is **not** flagged, because that only means Gilgamesh
   started capturing mid-session.
2. ``untrusted_resolver`` — the responder is not in the resolver allowlist. Judged **only
   once the allowlist is populated** (from DHCP, or set by the owner); an empty allowlist
   means no baseline, and accusing on no evidence would be worse than silence.
3. ``conflicting_answers`` — the same question receiving three or more *pairwise
   disjoint* answer sets from the same resolver inside the conflict window. Reported
   ``low``: it is a signal worth recording, not proof of an attack.

**False positives — this detector is the noisiest one in Gilgamesh.** Legitimate DNS
returns different answers on purpose:

* **CDNs, anycast and GSLB** hand different A records to different clients.
* **Round-robin DNS** rotates several addresses for one name by design.
* **Split-horizon DNS** deliberately answers differently inside and outside the LAN.
* **Forwarders and resolvers rewrite TTLs** to control client cache lifetimes.
* **Multiple resolvers** (ISP plus a VPN plus a Pi-hole) legitimately co-exist.

Four guards follow. Answers are compared on ``(name, type, rdata)`` and **TTL is
excluded**, because TTL rewriting alone must never look like a conflict. Conflicts are
counted **per resolver**, so two resolvers disagreeing is normal. Conflicting sets must be
*pairwise disjoint*, so a CDN that returns a superset does not trip it. And entries age
out of the window. The residual risk is a name genuinely served as round-robin from one
resolver: owners with that pattern should raise ``conflict_threshold`` (documented in the
web UI). **DoH/DoT is invisible to this detector** — encrypted DNS never appears on port
53 at all.

**Known limitation.** Transactions are keyed on ``(client, resolver, transaction id)``.
Transaction ids are only 16 bits and chosen by the client, so an attacker who guesses a
live id can still inject into a genuine query. Answering *first* with an id the client
has not yet used is the dominant attack and is what this detector catches.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.base import Detector

DNS_PORT = 53
DNS_RESPONSE = 1

#: Priority when a response trips more than one rule; the highest wins.
_REASON_SEVERITY: dict[str, Severity] = {
    "untrusted_resolver": Severity.HIGH,
    "response_without_matching_query": Severity.HIGH,
    "conflicting_answers": Severity.LOW,
}


@dataclass(frozen=True, slots=True)
class DnsConfig:
    """Tunable thresholds and the resolver trust list."""

    #: Resolvers allowed to answer. Empty means "not learned yet" — do not accuse.
    trusted_resolvers: frozenset[str] = frozenset()
    #: How long a query counts as "recently asked" and how long it stays answerable.
    no_match_window_seconds: float = 2.0
    #: Window and count of disjoint answer sets before reporting a conflict.
    conflict_window_seconds: float = 30.0
    conflict_threshold: int = 3
    #: TTL at or below which an answer is flagged in the evidence.
    suspicious_ttl: int = 1
    #: Cap on remembered answer sets per name, so a chatty name cannot grow memory.
    max_answer_sets: int = 8
    interface: str | None = None


@dataclass(frozen=True, slots=True)
class DnsFrame:
    """The parts of a DNS message this detector uses."""

    is_response: bool
    dns_id: int
    src_ip: str
    dst_ip: str
    qname: str | None
    #: Name taken from the answers, for responses that carry no question section.
    answer_name: str | None
    #: ``(name, type, rdata)`` triples. TTL is deliberately excluded — see module docstring.
    answers: frozenset[tuple[str, str, str]] = frozenset()
    min_ttl: int = 0
    authoritative: bool = False


@dataclass(frozen=True, slots=True)
class _PendingQuery:
    """A query we saw and are still willing to accept an answer for."""

    qname: str | None
    seen_at: float


def _name_text(value: object) -> str:
    """Normalise a DNS name: decode bytes, drop the root dot, lowercase."""
    text = value.decode("ascii", "replace") if isinstance(value, bytes) else str(value)
    return text.rstrip(".").lower()


def _rdata_text(value: object) -> str:
    """Normalise an answer's rdata for comparison."""
    if isinstance(value, bytes):
        return value.decode("ascii", "replace").rstrip(".").lower()
    return str(value).rstrip(".").lower()


def parse_dns(packet: object) -> DnsFrame | None:
    """Return the DNS content of ``packet``, or ``None`` if it is not DNS on port 53."""
    if not isinstance(packet, Packet):
        return None
    if IP not in packet or UDP not in packet or DNS not in packet:
        return None
    udp = packet[UDP]
    if int(udp.sport) != DNS_PORT and int(udp.dport) != DNS_PORT:
        return None

    dns = packet[DNS]
    ip = packet[IP]
    is_response = int(dns.qr) == DNS_RESPONSE

    # Scapy 2.8 made qd/an/ns/ar PacketListFields: they are lists now, and attribute
    # access on the list (e.g. ``dns.qd.qname``) trips a deprecation shim.
    questions = list(dns.qd)
    answers_raw = list(dns.an)

    qname: str | None = None
    if not is_response and questions and getattr(questions[0], "qname", None) is not None:
        qname = _name_text(questions[0].qname)

    answers: set[tuple[str, str, str]] = set()
    ttls: list[int] = []
    for record in answers_raw:
        rrname = getattr(record, "rrname", None)
        if rrname is None:
            continue
        answers.add(
            (
                _name_text(rrname),
                str(getattr(record, "type", "")),
                _rdata_text(getattr(record, "rdata", "")),
            )
        )
        ttls.append(int(getattr(record, "ttl", 0)))

    return DnsFrame(
        is_response=is_response,
        dns_id=int(dns.id),
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        qname=qname,
        answer_name=min((name for name, _, _ in answers), default=None),
        answers=frozenset(answers),
        min_ttl=min(ttls) if ttls else 0,
        authoritative=bool(int(dns.aa)),
    )


class DnsDetector(Detector):
    """Detects DNS spoofing by correlating queries with their responses."""

    name = "dns"

    def __init__(self, config: DnsConfig, clock: Callable[[], float] | None = None) -> None:
        self._config = config
        self._clock = clock if clock is not None else time.monotonic
        self._queries: dict[tuple[str, int], _PendingQuery] = {}
        self._last_query_from: dict[str, float] = {}
        self._answer_history: dict[
            tuple[str, str], list[tuple[float, frozenset[tuple[str, str, str]]]]
        ] = {}
        self._pending: list[Event] = []

    def events(self) -> list[Event]:
        """Return and clear the events produced by the most recent packet."""
        pending = self._pending
        self._pending = []
        return pending

    def process(self, packet: object) -> list[Event]:
        """Inspect one captured packet and return the events it triggered."""
        frame = parse_dns(packet)
        if frame is None:
            return []

        now = self._clock()
        if not frame.is_response:
            self._note_query(frame, now)
            self._pending = []
            return []

        query = self._queries.pop((frame.dst_ip, frame.dns_id), None)
        reasons = self._reasons_for(frame, query, now)
        qname = query.qname if (query is not None and query.qname) else frame.answer_name
        if self._record_answers(qname, frame):
            reasons.append("conflicting_answers")

        events: list[Event] = []
        if reasons:
            primary = max(reasons, key=lambda reason: _REASON_SEVERITY[reason].rank)
            events.append(self._event(frame, primary, reasons, qname))

        self._pending = events
        return events

    def _note_query(self, frame: DnsFrame, now: float) -> None:
        """Remember an outstanding query.

        The key is ``(client, transaction id)`` and deliberately excludes the resolver:
        the client picks the 16-bit transaction id, so it identifies the transaction on
        its own. Including the responder would mean a spoofed reply — sent from a
        different address — could never match its query, and every response through a
        forwarding resolver would look unmatched.
        """
        self._queries[(frame.src_ip, frame.dns_id)] = _PendingQuery(qname=frame.qname, seen_at=now)
        self._last_query_from[frame.src_ip] = now

    def _reasons_for(self, frame: DnsFrame, query: _PendingQuery | None, now: float) -> list[str]:
        """Decide which spoofing rules this response breaks."""
        reasons: list[str] = []
        window = self._config.no_match_window_seconds

        matched = query is not None and now - query.seen_at <= window
        if not matched:
            last_query = self._last_query_from.get(frame.dst_ip)
            recently_asked = last_query is not None and now - last_query <= window
            # `query is not None` means we watched this transaction age out, which is
            # suspicious. Otherwise we only accuse when the client was actively asking.
            if query is not None or recently_asked:
                reasons.append("response_without_matching_query")

        if self._config.trusted_resolvers and frame.src_ip not in self._config.trusted_resolvers:
            reasons.append("untrusted_resolver")

        return reasons

    def _record_answers(self, qname: str | None, frame: DnsFrame) -> bool:
        """Remember an answer set and report whether it conflicts with earlier ones."""
        if not frame.answers or qname is None:
            return False

        key = (qname, frame.src_ip)
        now = self._clock()
        window = self._config.conflict_window_seconds
        history = self._answer_history.setdefault(key, [])
        history[:] = [entry for entry in history if now - entry[0] < window]

        if frame.answers in {answers for _, answers in history}:
            return False

        history.append((now, frame.answers))
        del history[: max(0, len(history) - self._config.max_answer_sets)]
        return self._disjoint_set_count(history) >= self._config.conflict_threshold

    @staticmethod
    def _disjoint_set_count(
        history: list[tuple[float, frozenset[tuple[str, str, str]]]],
    ) -> int:
        """Count answer sets that share no record with any other set.

        Overlap is what separates a genuine conflict from a CDN that returns the same
        pool plus an extra record.
        """
        count = 0
        for index, (_, current) in enumerate(history):
            others = [answers for position, (_, answers) in enumerate(history) if position != index]
            if all(current.isdisjoint(other) for other in others):
                count += 1
        return count

    def _event(self, frame: DnsFrame, reason: str, reasons: list[str], qname: str | None) -> Event:
        return Event(
            type=EventType.DNS_SPOOF,
            severity=_REASON_SEVERITY[reason],
            detector=self.name,
            summary=f"{reason.replace('_', ' ')} for {qname or 'unknown name'}"
            f" (id {frame.dns_id}) from {frame.src_ip}",
            src_ip=frame.src_ip,
            dst_ip=frame.dst_ip,
            interface=self._config.interface,
            details={
                "reason": reason,
                "all_reasons": reasons,
                "dns_id": frame.dns_id,
                "qname": qname,
                "answers": sorted(frame.answers),
                "min_ttl": frame.min_ttl,
                "suspicious_ttl": frame.min_ttl <= self._config.suspicious_ttl,
                "authoritative": frame.authoritative,
            },
        )
