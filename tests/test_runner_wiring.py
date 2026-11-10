"""The sensor's start-up wiring: configuration, gateway discovery, rules, Suricata.

``sensors/runner.py`` is where every piece meets — the owner's stored choices, the
capture source, the detectors, the Suricata tailer — so these tests check the seams
rather than the parts: stored parameters reach the detectors, a disabled rule really
silences an alert end to end, the pipeline's escalated severity is what gets stored, and
starting with no capture source is a loud configuration error instead of silence.
"""

from __future__ import annotations

import json
import signal
from collections.abc import Iterator
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import wrpcap

from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.pipeline import Pipeline, PipelineSettings
from gilgamesh.rules import RuleConfigService, default_catalogue
from gilgamesh.sensors.base import PacketDetector
from gilgamesh.sensors.gate import RuleGate
from gilgamesh.sensors.runner import (
    SensorRunner,
    SensorRunnerConfig,
    build_detectors,
    detect_default_gateway,
    main,
)
from gilgamesh.sensors.scan_flood import ScanDetector

GATEWAY_IP = "10.0.0.1"
GATEWAY_MAC = "aa:bb:cc:00:00:01"
HOST_IP = "10.0.0.2"
HOST_MAC = "aa:bb:cc:00:00:02"
ATTACKER_MAC = "de:ad:be:ef:00:01"
MAC_ZERO = "00:00:00:00:00:00"


def arp_reply(hwsrc: str, psrc: str, hwdst: str, pdst: str) -> Packet:
    return Ether(src=hwsrc, dst=hwdst) / ARP(op=2, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst)


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    yield database
    database.close()


@pytest.fixture
def rules(db: Database) -> RuleConfigService:
    return RuleConfigService(db, default_catalogue())


# --- gateway discovery --------------------------------------------------------


def test_default_gateway_is_read_from_the_routing_table(tmp_path: Path) -> None:
    """192.168.1.1 = C0 A8 01 01, printed little-endian as 0101A8C0."""
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    )

    assert detect_default_gateway(route) == "192.168.1.1"


def test_no_default_route_means_no_gateway(tmp_path: Path) -> None:
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    )

    assert detect_default_gateway(route) is None


def test_a_missing_route_file_is_not_an_error(tmp_path: Path) -> None:
    """The gateway check is optional; a missing /proc file must not stop the sensor."""
    assert detect_default_gateway(tmp_path / "does-not-exist") is None


# --- detectors from stored parameters ----------------------------------------


def test_build_detectors_reads_stored_parameters(rules: RuleConfigService) -> None:
    """The owner set a threshold on the Rules page; the detector must use it.

    This is checked behaviourally: with ``port_threshold`` at its minimum of 5, six SYNs
    to six ports are a scan, where the shipped default of 20 says nothing. If the mapping
    between the catalogue and the detector config broke, this test fails while every unit
    test of the detector itself still passes.
    """
    packets = [
        IP(src=HOST_IP, dst="10.0.0.9") / TCP(dport=port, flags="S") for port in range(1000, 1006)
    ]

    rules.set_params("scan.vertical", {"port_threshold": 5})
    lowered = _scan_detector(rules)
    assert [event.type for event in _feed(lowered, packets)] == [EventType.PORT_SCAN]

    rules.set_params("scan.vertical", {"port_threshold": 20})
    default = _scan_detector(rules)
    assert _feed(default, packets) == []


def _scan_detector(rules: RuleConfigService) -> ScanDetector:
    detectors = build_detectors(rules, gateway_ip=None, interface="br0")
    return next(detector for detector in detectors if isinstance(detector, ScanDetector))


def _feed(detector: ScanDetector, packets: list[Packet]) -> list[Event]:
    events: list[Event] = []
    for packet in packets:
        events.extend(detector.process(packet))
    return events


def test_build_detectors_covers_every_rule_family(rules: RuleConfigService) -> None:
    detectors = build_detectors(rules, gateway_ip=GATEWAY_IP, interface=None)

    names = sorted(detector.name for detector in detectors)
    assert names == ["arp", "dhcp", "dns", "inventory", "scan_flood"]


def test_build_detectors_survives_a_damaged_parameter_row(
    db: Database, rules: RuleConfigService
) -> None:
    """A hand-edited row must not stop the sensor from starting.

    ``set_params`` validates, so the damage is applied directly to the database, the way
    an interrupted write or an older schema would leave it: first unreadable JSON, then a
    readable object holding the wrong type for a parameter.
    """
    db.execute(
        "UPDATE rule_settings SET params = ? WHERE rule_id = ?", ("{]not json", "scan.syn_flood")
    )

    detectors = build_detectors(rules, gateway_ip=None, interface=None)
    assert any(isinstance(detector, ScanDetector) for detector in detectors)

    rules.set_params("scan.syn_flood", {"syn_threshold": 200})
    db.execute(
        "UPDATE rule_settings SET params = ? WHERE rule_id = ?",
        ('{"syn_threshold": "very many"}', "scan.syn_flood"),
    )

    detectors = build_detectors(rules, gateway_ip=None, interface=None)
    assert any(isinstance(detector, ScanDetector) for detector in detectors)


# --- rules end to end ---------------------------------------------------------


def test_disabled_rule_silences_the_alert_end_to_end(
    tmp_path: Path, db: Database, rules: RuleConfigService
) -> None:
    """Toggle the switch off on the Rules page → the sensor stores nothing for it."""
    packets: list[Packet] = [
        Ether(src=HOST_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=HOST_MAC, psrc=HOST_IP, hwdst=MAC_ZERO, pdst=GATEWAY_IP),
        arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP),
        arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP),
    ]
    path = tmp_path / "spoof.pcap"
    wrpcap(str(path), packets)

    database = db
    detector = _arp_detector()
    runner = SensorRunner(
        [detector],
        database,
        Pipeline(),
        SensorRunnerConfig(source=path, interface="br0"),
        gate=RuleGate(rules),
    )

    runner.run_once()
    assert [event.details["reason"] for event in database.list_events()] == ["gateway_mac_changed"]

    rules.set_enabled("arp.gateway_mac_changed", False)

    database.execute("DELETE FROM events")
    runner.run_once()

    assert database.list_events() == []


def _arp_detector() -> PacketDetector:
    from gilgamesh.sensors.arp import ArpConfig, ArpDetector

    return ArpDetector(ArpConfig(gateway_ip=GATEWAY_IP, warmup_seconds=0.0))


# --- escalated severity is what gets stored -----------------------------------


class _Clock:
    """Manually advanced monotonic clock for the pipeline."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _event(summary: str = "Gateway MAC changed", severity: Severity = Severity.MEDIUM) -> Event:
    return Event(
        type=EventType.ARP_SPOOF,
        severity=severity,
        detector="arp",
        summary=summary,
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
    )


def test_repeated_events_update_one_persisted_incident(db: Database) -> None:
    """One sustained attack must leave one incident row whose count keeps rising."""
    clock = _Clock()
    pipeline = Pipeline(
        PipelineSettings(
            dedup_window=0.0,
            cooldown=0.0,
            aggregate_window=900.0,
            rate_limit_count=100,
            escalate_at=100,
        ),
        clock=clock,
    )
    runner = SensorRunner([], db, pipeline, SensorRunnerConfig(interface="br0"))

    for _ in range(5):
        runner.submit_event(_event())
        clock.now += 1.0

    stored = db.list_events()
    incidents = db.query("SELECT * FROM incidents")
    assert len(stored) == 1
    assert len(incidents) == 1
    assert incidents[0]["count"] == 5
    assert stored[0].incident_id == incidents[0]["id"]
    assert stored[0].incident_count == 5


def test_cooldown_and_rate_limit_drops_are_still_counted(db: Database) -> None:
    """Suppressing the announcement must not erase the fact that the attack continued."""
    clock = _Clock()
    pipeline = Pipeline(
        PipelineSettings(
            dedup_window=0.0,
            cooldown=300.0,
            aggregate_window=900.0,
            rate_limit_count=100,
            escalate_at=100,
        ),
        clock=clock,
    )
    runner = SensorRunner([], db, pipeline, SensorRunnerConfig(interface="br0"))

    assert runner.submit_event(_event()) is True
    clock.now += 10.0
    assert runner.submit_event(_event()) is False  # cooldown
    clock.now += 10.0
    assert runner.submit_event(_event()) is False  # cooldown again

    assert db.query("SELECT count FROM incidents")[0]["count"] == 3


def test_rate_limited_events_are_counted(db: Database) -> None:
    clock = _Clock()
    pipeline = Pipeline(
        PipelineSettings(
            dedup_window=0.0,
            cooldown=0.0,
            aggregate_window=900.0,
            rate_limit_count=1,
            rate_limit_window=60.0,
            escalate_at=100,
        ),
        clock=clock,
    )
    runner = SensorRunner([], db, pipeline, SensorRunnerConfig(interface="br0"))

    assert runner.submit_event(_event()) is True
    clock.now += 1.0
    assert runner.submit_event(_event()) is False  # rate limited

    assert db.query("SELECT count FROM incidents")[0]["count"] == 2


def test_one_hour_of_continuous_attack_stores_a_handful_of_rows_and_counts_them_all(
    db: Database,
) -> None:
    """The seam the audit report named: one hour of attack, one incident, honest count.

    Default thresholds, an event every six seconds for an hour (600 sightings). The
    database must stay small — that is the whole point of dedup/cooldown/rate limiting —
    while the incident count still reflects every sighting, including the suppressed
    ones, so the UI can say "seen 600 times".
    """
    clock = _Clock()
    runner = SensorRunner([], db, Pipeline(clock=clock), SensorRunnerConfig(interface="br0"))

    for _ in range(600):
        runner.submit_event(_event())
        clock.now += 6.0

    stored = db.list_events()
    incidents = db.query("SELECT * FROM incidents")
    assert len(incidents) == 1
    assert incidents[0]["count"] == 600
    assert len(stored) <= 3
    assert stored[-1].incident_count == 600


def test_incident_ids_come_from_the_database_not_a_restarting_counter(db: Database) -> None:
    """A sensor restart must not make new incidents reuse an old id."""
    first = SensorRunner([], db, Pipeline(), SensorRunnerConfig(interface="br0"))
    assert first.submit_event(_event()) is True
    second = SensorRunner([], db, Pipeline(), SensorRunnerConfig(interface="br0"))
    assert second.submit_event(_event()) is True

    ids = [event.incident_id for event in sorted(db.list_events(), key=lambda e: e.ts)]
    assert ids[0] is not None and ids[1] is not None
    assert ids[0] != ids[1]
    assert db.query("SELECT COUNT(*) AS n FROM incidents")[0]["n"] == 2


def test_escalated_incident_is_stored_at_the_escalated_severity(
    tmp_path: Path, db: Database
) -> None:
    """A re-announcement must not be stored as though it were the first, quiet alert."""
    pipeline = Pipeline(
        PipelineSettings(
            dedup_window=0.0,
            cooldown=0.0,
            aggregate_window=900.0,
            escalate_at=2,
            rate_limit_count=100,
        )
    )
    runner = SensorRunner([], db, pipeline, SensorRunnerConfig(interface="br0"))

    def next_event() -> Event:
        # Each escalation is triggered by a further packet, so each event is its own
        # object with its own id — the same situation the sensor is in.
        return Event(
            type=EventType.ARP_SPOOF,
            severity=Severity.MEDIUM,
            detector="arp",
            summary="Gateway MAC changed",
            details={"reason": "gateway_mac_changed"},
        )

    assert runner.submit_event(next_event()) is True
    assert runner.submit_event(next_event()) is True  # the escalation re-announcement

    stored = sorted(db.list_events(), key=lambda entry: entry.ts)
    assert [entry.severity for entry in stored] == [Severity.MEDIUM, Severity.HIGH]


# --- Suricata tailer through main() -------------------------------------------


def _eve_alert(signature: str = "ET SCAN Potential SSH Scan") -> str:
    return json.dumps(
        {
            "timestamp": "2026-10-18T12:00:00.000000+0000",
            "flow_id": 42,
            "event_type": "alert",
            "src_ip": "203.0.113.9",
            "src_port": 44444,
            "dest_ip": "10.0.0.5",
            "dest_port": 22,
            "proto": "TCP",
            "in_iface": "br0",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2001219,
                "rev": 19,
                "signature": signature,
                "category": "Attempted Information Leak",
                "severity": 1,
            },
        }
    )


def test_main_tails_suricata_and_exits_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The production entry point, end to end: replay a pcap, ingest one EVE alert.

    Everything is driven through environment variables exactly as the systemd unit
    drives it. The Suricata line is what proves a non-packet event reaches the same
    pipeline and database as the detectors' own alerts.
    """
    pcap = tmp_path / "quiet.pcap"
    wrpcap(str(pcap), [arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)])
    eve = tmp_path / "eve.json"
    eve.write_text(_eve_alert() + "\n")
    data_dir = tmp_path / "data"
    # Seed the durable tail position at byte zero, as a sensor that was already
    # following this log would have. A fresh open deliberately ignores history.
    seed = Database(data_dir / "gilgamesh.db")
    seed.initialize()
    seed.set_setting(
        f"suricata_eve_position:{eve}",
        json.dumps({"inode": eve.stat().st_ino, "offset": 0}),
    )
    seed.close()

    monkeypatch.setenv("GILGAMESH_DATA_DIR", str(data_dir))
    monkeypatch.setenv("GILGAMESH_PCAP", str(pcap))
    monkeypatch.delenv("GILGAMESH_INTERFACE", raising=False)
    monkeypatch.setenv("GILGAMESH_SURICATA_EVE_PATH", str(eve))
    monkeypatch.delenv("GILGAMESH_GATEWAY_IP", raising=False)

    saved = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        with pytest.raises(SystemExit) as exit_info:
            main()
    finally:
        for sig, handler in saved.items():
            signal.signal(sig, handler)

    assert exit_info.value.code == 0

    database = Database(data_dir / "gilgamesh.db")
    try:
        events = database.list_events()
        device_macs = [record.mac for record in DeviceStore(database).list()]
        behaviour_status = database.get_setting("behaviour_status")
    finally:
        database.close()
    assert [event.detector for event in events] == ["suricata"]
    assert events[0].details["signature"] == "ET SCAN Potential SSH Scan"
    # Detection of the packet source also happened: the seen device was mirrored.
    assert device_macs == [GATEWAY_MAC]
    # The behaviour service was wired in and published its final status on shutdown.
    assert behaviour_status is not None


def test_main_refuses_to_run_without_a_capture_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sensor that silently detects nothing is worse than one that refuses to start."""
    monkeypatch.setenv("GILGAMESH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("GILGAMESH_INTERFACE", raising=False)
    monkeypatch.delenv("GILGAMESH_PCAP", raising=False)

    with pytest.raises(SystemExit) as exit_info:
        main()

    assert exit_info.value.code == 2


def test_main_refuses_to_run_when_the_data_directory_is_unusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocker = tmp_path / "blocked"
    blocker.write_text("this is a file, not a directory")
    monkeypatch.setenv("GILGAMESH_DATA_DIR", str(blocker))
    monkeypatch.setenv("GILGAMESH_PCAP", str(tmp_path / "irrelevant.pcap"))
    monkeypatch.delenv("GILGAMESH_INTERFACE", raising=False)

    with pytest.raises(SystemExit) as exit_info:
        main()

    assert exit_info.value.code == 2


# --- interface label plumbing --------------------------------------------------


def test_the_runner_stamps_the_configured_label(tmp_path: Path, db: Database) -> None:
    path = tmp_path / "label.pcap"
    wrpcap(str(path), [arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)])
    runner = SensorRunner(
        [_arp_detector()],
        db,
        Pipeline(),
        SensorRunnerConfig(source=path, interface_label="br0 (span)"),
    )

    runner.run_once()

    assert db.list_events()[0].interface == "br0 (span)"


# --- capture source wiring and health counters ---------------------------------


class _FakeSource:
    """A finite packet source that also reports capture drops, like ``LiveSource``."""

    description = "fake:capture"

    def __init__(self, packets: list[Packet], dropped: int = 0) -> None:
        self._packets = packets
        self.dropped = dropped

    def __iter__(self) -> Iterator[Packet]:
        return iter(self._packets)


def test_runner_passes_the_configured_bpf_to_the_source(db: Database) -> None:
    """``SensorRunnerConfig.bpf`` used to be dead configuration."""
    seen: dict[str, object] = {}

    def factory(**kwargs: object) -> _FakeSource:
        seen.update(kwargs)
        return _FakeSource([])

    runner = SensorRunner(
        [],
        db,
        Pipeline(),
        SensorRunnerConfig(interface="br0", bpf="arp or tcp"),
        source_factory=factory,
    )

    runner.run_once()

    assert seen == {"interface": "br0", "path": None, "bpf": "arp or tcp"}


def test_runner_publishes_capture_and_drop_counts_for_the_health_page(db: Database) -> None:
    packet = arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)

    def factory(**_: object) -> _FakeSource:
        return _FakeSource([packet, packet], dropped=3)

    runner = SensorRunner(
        [],
        db,
        Pipeline(),
        SensorRunnerConfig(interface="br0"),
        source_factory=factory,
    )

    runner.run_once()

    assert db.get_setting("sensor_packets_processed") == "2"
    assert db.get_setting("sensor_packets_dropped") == "3"
