"""Live-capture seams: the BPF really sees handshake packets, and the queue is bounded.

The scan/flood detectors need SYN, SYN-ACK, FIN and RST. The live filter used to carry
only ARP/DNS/DHCP/ICMP, so those detectors could never fire on a real interface while
every PCAP replay test still passed. These tests compile the shipped filter with the
kernel's own BPF compiler (``tcpdump -d``) and filter a real capture with it, which is as
close to "does the interface deliver a SYN to Python?" as a dev machine can get without
touching a network.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import wrpcap

from gilgamesh.sensors.capture import DEFAULT_BPF, LiveSource, make_source

TCPDUMP = shutil.which("tcpdump")


def tcp_packet(flags: str, dport: int = 443) -> Packet:
    return (
        Ether(src="aa:bb:cc:00:00:02", dst="aa:bb:cc:00:00:01")
        / IP(src="10.0.0.2", dst="10.0.0.9")
        / TCP(sport=40000, dport=dport, flags=flags)
    )


def filtered_lines(path: Path, expression: str) -> list[str]:
    """Return what tcpdump's BPF engine keeps from ``path`` for ``expression``."""
    assert TCPDUMP is not None
    result = subprocess.run(  # noqa: S603 - fixed argv; the file is a test fixture
        [TCPDUMP, "-nn", "-r", str(path), expression],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return [line for line in result.stdout.splitlines() if line.strip()]


@pytest.mark.skipif(TCPDUMP is None, reason="tcpdump is not installed")
def test_shipped_filter_accepts_the_packets_the_detectors_need(tmp_path: Path) -> None:
    """A SYN, a SYN-ACK, a FIN and a RST must all survive the real BPF."""
    path = tmp_path / "handshake.pcap"
    wrpcap(
        str(path),
        [
            tcp_packet("S"),
            tcp_packet("SA"),
            tcp_packet("FA"),
            tcp_packet("R"),
        ],
    )

    kept = filtered_lines(path, DEFAULT_BPF)

    assert len(kept) == 4


@pytest.mark.skipif(TCPDUMP is None, reason="tcpdump is not installed")
def test_shipped_filter_still_accepts_the_non_tcp_detectors(tmp_path: Path) -> None:
    """Adding TCP must not regress ARP, DNS or DHCP capture."""
    arp = Ether(src="aa:bb:cc:00:00:02", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="10.0.0.2")
    dns = (
        Ether(src="aa:bb:cc:00:00:02", dst="aa:bb:cc:00:00:01")
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=5353, dport=53)
        / DNS(qd=DNSQR(qname="example.invalid"))
    )
    dhcp = (
        Ether(src="aa:bb:cc:00:00:02", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")  # noqa: S104 - DHCP discover address
        / UDP(sport=68, dport=67)
    )
    path = tmp_path / "control.pcap"
    wrpcap(str(path), [arp, dns, dhcp])

    assert len(filtered_lines(path, DEFAULT_BPF)) == 3


@pytest.mark.skipif(TCPDUMP is None, reason="tcpdump is not installed")
def test_shipped_filter_drops_bulk_tcp_payload(tmp_path: Path) -> None:
    """The point of the filter is to keep the Pi's CPU off ordinary data traffic."""
    path = tmp_path / "bulk.pcap"
    wrpcap(str(path), [tcp_packet("PA"), tcp_packet("A")])

    assert filtered_lines(path, DEFAULT_BPF) == []


def test_make_source_passes_the_configured_filter_to_live_capture() -> None:
    """``SensorRunnerConfig.bpf`` must reach ``make_source``; it used to be ignored."""
    custom = "arp or (tcp[tcpflags] & tcp-syn != 0)"

    source = make_source(interface="br0", bpf=custom)

    assert isinstance(source, LiveSource)
    assert source.bpf == custom


def test_live_source_counts_packets_dropped_when_the_queue_is_full() -> None:
    """An unbounded queue is a memory leak under load; the newest packet is dropped."""
    packets: list[Packet] = [tcp_packet("S") for _ in range(3)]
    source = LiveSource("br0", max_queue=2)

    for packet in packets:
        source._put(packet)  # pyright: ignore[reportPrivateUsage] - the sniffer thread's hook

    assert source.dropped == 1
