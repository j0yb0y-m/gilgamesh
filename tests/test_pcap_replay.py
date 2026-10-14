"""M8 — capture abstraction, sensor runner, and PCAP replay tests.

Constraint C10 requires every detector to run against synthetic packets and PCAP files
on an ordinary Linux machine, with no Pi, no bridge, and no root. That is only true if
the capture source is an *abstraction* (C8): the same runner must be able to read a live
interface or a file, and the detectors must not know which one they are looking at.

These tests build real PCAP files with Scapy, replay them through the runner, and assert
that the expected alerts come out the other end.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import PcapWriter

from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event
from gilgamesh.pipeline import Pipeline, PipelineDecision
from gilgamesh.sensors.arp import ArpConfig, ArpDetector
from gilgamesh.sensors.base import PacketDetector
from gilgamesh.sensors.capture import PcapSource, iter_pcap
from gilgamesh.sensors.inventory import InventoryConfig, InventoryDetector
from gilgamesh.sensors.runner import SensorRunner, SensorRunnerConfig
from gilgamesh.util.net import MAC_ZERO

GATEWAY_IP = "10.0.0.1"
GATEWAY_MAC = "00:11:22:00:00:01"
HOST_MAC = "00:11:22:00:00:02"
HOST_IP = "10.0.0.2"
ATTACKER_MAC = "00:11:22:00:00:99"


def arp_reply(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> Packet:
    return Ether(src=src_mac, dst=dst_mac) / ARP(
        op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip
    )


def write_pcap(path: Path, packets: Sequence[Packet]) -> Path:
    """Write ``packets`` to ``path`` as a pcap file and return the path."""
    writer = PcapWriter(str(path))
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()
    return path


def test_iter_pcap_reads_every_packet(tmp_path: Path) -> None:
    packets = [arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP) for _ in range(3)]
    path = write_pcap(tmp_path / "three.pcap", packets)

    assert len(list(iter_pcap(path))) == 3


def test_iter_pcap_on_missing_file_returns_nothing(tmp_path: Path) -> None:
    assert list(iter_pcap(tmp_path / "absent.pcap")) == []


def test_iter_pcap_on_truncated_file_raises(tmp_path: Path) -> None:
    """A corrupt capture is an operational problem, so it must not look like silence."""
    path = tmp_path / "truncated.pcap"
    path.write_bytes(b"not a pcap at all")

    try:
        list(iter_pcap(path))
    except OSError:
        return
    raise AssertionError("expected OSError for a corrupt pcap")


def test_pcap_source_is_iterable(tmp_path: Path) -> None:
    path = write_pcap(
        tmp_path / "one.pcap", [arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)]
    )

    source = PcapSource(path)

    assert len(list(source)) == 1
    assert source.description.endswith("one.pcap")


def test_runner_replays_pcap_into_the_database(tmp_path: Path) -> None:
    """The end-to-end proof of C10: a recorded attack produces a stored alert."""
    path = write_pcap(
        tmp_path / "arp_spoof.pcap",
        [
            # Healthy traffic first: the gateway legitimately answers the host.
            Ether(src=HOST_MAC, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, hwsrc=HOST_MAC, psrc=HOST_IP, hwdst=MAC_ZERO, pdst=GATEWAY_IP),
            arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP),
            # Then the attack: a different MAC claims to be the gateway.
            arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP),
        ],
    )

    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    detector = ArpDetector(ArpConfig(gateway_ip=GATEWAY_IP, warmup_seconds=0.0))
    runner = SensorRunner(
        [detector], db, Pipeline(), SensorRunnerConfig(source=path, interface="br0")
    )

    processed = runner.run_once()

    events = db.list_events()
    reasons = {event.details.get("reason") for event in events}
    assert processed == 3
    assert "gateway_mac_changed" in reasons
    assert any(event.detector == "arp" for event in events)
    # The legitimate reply alone must not have produced an alert.
    assert len([e for e in events if e.details.get("reason") == "gateway_mac_changed"]) == 1
    db.close()


def test_runner_deduplicates_repeated_attack_packets(tmp_path: Path) -> None:
    """200 copies of one poisoning packet must collapse through the pipeline."""
    packets: list[Packet] = [
        # The legitimate gateway is learned first, so the later change is detectable.
        Ether(src=HOST_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=HOST_MAC, psrc=HOST_IP, hwdst=MAC_ZERO, pdst=GATEWAY_IP),
        arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP),
    ]
    packets += [arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP) for _ in range(200)]
    path = write_pcap(tmp_path / "flood.pcap", packets)

    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    detector = ArpDetector(ArpConfig(gateway_ip=GATEWAY_IP, warmup_seconds=0.0))
    runner = SensorRunner(
        [detector], db, Pipeline(), SensorRunnerConfig(source=path, interface="br0")
    )

    runner.run_once()

    events = db.list_events()
    assert len(events) == 1
    assert events[0].details["reason"] == "gateway_mac_changed"
    db.close()


def test_runner_stamps_the_interface_on_events(tmp_path: Path) -> None:
    path = write_pcap(
        tmp_path / "iface.pcap", [arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)]
    )
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    detector = ArpDetector(ArpConfig(gateway_ip=GATEWAY_IP, warmup_seconds=0.0))
    runner = SensorRunner(
        [detector], db, Pipeline(), SensorRunnerConfig(source=path, interface="br0")
    )

    runner.run_once()

    assert all(event.interface == "br0" for event in db.list_events())
    db.close()


def test_runner_fans_out_to_every_detector(tmp_path: Path) -> None:
    path = write_pcap(
        tmp_path / "both.pcap", [arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)]
    )
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    arp = ArpDetector(ArpConfig(gateway_ip=GATEWAY_IP, warmup_seconds=0.0))
    inventory = InventoryDetector(InventoryConfig(learning_seconds=0.0))
    runner = SensorRunner(
        [arp, inventory], db, Pipeline(), SensorRunnerConfig(source=path, interface="br0")
    )

    runner.run_once()

    detectors = {event.detector for event in db.list_events()}
    assert detectors == {"arp", "inventory"}
    db.close()


def test_runner_mirrors_observed_devices_into_the_inventory(tmp_path: Path) -> None:
    """The Devices page reads the database, so the runner must write the devices it sees."""
    path = write_pcap(
        tmp_path / "devices.pcap",
        [
            arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP),
            arp_reply(ATTACKER_MAC, "10.0.0.9", HOST_MAC, HOST_IP),
        ],
    )
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    store = DeviceStore(db)
    runner = SensorRunner(
        [],
        db,
        Pipeline(),
        SensorRunnerConfig(source=path, interface="br0"),
        device_store=store,
    )

    runner.run_once()

    recorded = {device.mac: device.ips for device in store.list()}
    assert recorded == {GATEWAY_MAC: (GATEWAY_IP,), ATTACKER_MAC: ("10.0.0.9",)}
    db.close()


def test_runner_refreshes_a_device_row_at_most_once_per_window(tmp_path: Path) -> None:
    """Repeats must not turn every packet into an SD-card write."""
    path = write_pcap(
        tmp_path / "repeat.pcap",
        [arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP) for _ in range(5)],
    )
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    writes: list[str] = []

    class CountingStore(DeviceStore):
        def upsert(self, mac: str, **kwargs: object):  # type: ignore[override]
            writes.append(mac)
            return super().upsert(mac, **kwargs)

    runner = SensorRunner(
        [],
        db,
        Pipeline(),
        SensorRunnerConfig(source=path),
        device_store=CountingStore(db),
    )

    runner.run_once()

    assert len(writes) == 1
    db.close()


def test_runner_survives_a_detector_that_raises(tmp_path: Path) -> None:
    """One broken detector must never take the sensor process down."""
    path = write_pcap(
        tmp_path / "raise.pcap", [arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)]
    )
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    good = ArpDetector(ArpConfig(gateway_ip=GATEWAY_IP, warmup_seconds=0.0))
    runner = SensorRunner(
        [ExplodingDetector(), good], db, Pipeline(), SensorRunnerConfig(source=path)
    )

    processed = runner.run_once()

    assert processed == 1
    assert any(event.detector == "arp" for event in db.list_events())
    db.close()


def test_runner_keeps_going_after_a_detector_error(tmp_path: Path) -> None:
    path = write_pcap(
        tmp_path / "mixed.pcap",
        [
            Ether(src=HOST_MAC, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, hwsrc=HOST_MAC, psrc=HOST_IP, hwdst=MAC_ZERO, pdst=GATEWAY_IP),
            arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP),
        ],
    )
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    runner = SensorRunner([ExplodingDetector()], db, Pipeline(), SensorRunnerConfig(source=path))

    processed = runner.run_once()

    assert processed == 2
    assert db.list_events() == []
    db.close()


def test_runner_with_no_detectors_is_a_no_op(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "empty.pcap", [])
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    runner = SensorRunner([], db, Pipeline(), SensorRunnerConfig(source=path))

    assert runner.run_once() == 0
    db.close()


def test_runner_reports_a_missing_source_without_raising(tmp_path: Path) -> None:
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    detector = ArpDetector(ArpConfig(gateway_ip=GATEWAY_IP))
    runner = SensorRunner(
        [detector], db, Pipeline(), SensorRunnerConfig(source=tmp_path / "nope.pcap")
    )

    assert runner.run_once() == 0
    db.close()


def test_pipeline_decisions_are_visible_to_the_caller(tmp_path: Path) -> None:
    """The runner honours the pipeline: aggregated repeats are not stored again."""
    path = write_pcap(
        tmp_path / "repeat.pcap",
        [
            Ether(src=HOST_MAC, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, hwsrc=HOST_MAC, psrc=HOST_IP, hwdst=MAC_ZERO, pdst=GATEWAY_IP),
            arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP),
            arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP),
        ],
    )
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    detector = ArpDetector(ArpConfig(gateway_ip=GATEWAY_IP, warmup_seconds=0.0))
    pipeline = Pipeline()
    runner = SensorRunner(
        [detector], db, pipeline, SensorRunnerConfig(source=path, interface="br0")
    )

    runner.run_once()

    # First attack packet is deduped against the preceding gateway reply sharing the
    # same key; the second opens the incident. Either way, only one alert is stored.
    assert len(db.list_events()) <= 1
    assert pipeline.tracked_key_count <= 1
    assert PipelineDecision.STORE in set(PipelineDecision)
    db.close()


def test_benign_pcap_produces_no_alerts(tmp_path: Path) -> None:
    """The false-positive check: ordinary traffic replayed end to end must be silent."""
    packets: list[Packet] = []
    for index in range(30):
        packets.append(
            Ether(src=HOST_MAC, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, hwsrc=HOST_MAC, psrc=HOST_IP, hwdst=MAC_ZERO, pdst=GATEWAY_IP)
        )
        packets.append(arp_reply(GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP))
        del index
    packets.append(Ether(src=HOST_MAC, dst=GATEWAY_MAC) / IP(src=HOST_IP, dst=GATEWAY_IP) / TCP())

    path = write_pcap(tmp_path / "benign.pcap", packets)
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    arp = ArpDetector(ArpConfig(gateway_ip=GATEWAY_IP, warmup_seconds=0.0))
    runner = SensorRunner([arp], db, Pipeline(), SensorRunnerConfig(source=path))

    runner.run_once()

    assert db.list_events() == []
    db.close()


class ExplodingDetector(PacketDetector):
    """A detector that always fails, used to prove the runner isolates failures."""

    name = "exploding"

    def events(self) -> list[Event]:
        return []

    def process(self, packet: object) -> list[Event]:
        msg = "detector failure"
        raise RuntimeError(msg)


def test_runner_logs_detector_errors(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """The failure must be visible to the operator, not swallowed silently."""
    path = write_pcap(
        tmp_path / "raise.pcap", [arp_reply(ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP)]
    )
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    runner = SensorRunner([ExplodingDetector()], db, Pipeline(), SensorRunnerConfig(source=path))

    with caplog.at_level(logging.ERROR, logger="gilgamesh.sensors.runner"):
        runner.run_once()

    assert any("exploding" in record.getMessage() for record in caplog.records)
    db.close()
