"""Packet sources: a live interface or a PCAP file.

Constraint C8 requires the capture source to be an abstraction, and C10 requires every
detector to be testable on a development machine with no Pi and no privileges. Both fall
out of the same design: the sensor runner is handed a :class:`PacketSource` and cannot
tell whether the packets came off a wire or out of a file. That is what lets the whole
detection stack be exercised by replaying a recorded capture.

**Threading.** Live capture runs through Scapy's ``AsyncSniffer``, which owns its own
thread. It is deliberately *not* run on the asyncio event loop: ``sniff()`` blocks, and
blocking the loop would stall the web server that shares this box.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from queue import Queue
from typing import Protocol

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader

logger = logging.getLogger(__name__)

#: Berkeley Packet Filter applied before anything reaches Python. On a home uplink this
#: is the difference between a few thousand packets per second and a saturated CPU: it
#: drops the bulk of TCP payload traffic in the kernel before Scapy ever sees it.
DEFAULT_BPF = "arp or (udp port 53) or (udp port 67 or 68) or icmp or icmp6"


class PacketSource(Protocol):
    """Something that yields packets, whether live or recorded."""

    @property
    def description(self) -> str:
        """Human-readable identity, used in logs and health output."""
        ...

    def __iter__(self) -> Iterator[Packet]:
        """Yield packets until the source is exhausted or stopped."""
        ...


#: Little- and big-endian, microsecond- and nanosecond-resolution pcap magic numbers.
_PCAP_MAGICS = frozenset(
    {
        b"\xa1\xb2\xc3\xd4",
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x4d\x3c\xb2\xa1",
    }
)


def _is_pcap(path: Path) -> bool:
    """Check the file magic before handing it to Scapy.

    ``PcapReader`` opens the file in its constructor and leaves it open when header
    parsing fails, so a corrupt capture would leak a file descriptor on every call.
    Reading four bytes first gives a clearer error and no leak.
    """
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        return False
    return magic in _PCAP_MAGICS


def iter_pcap(path: Path) -> Iterator[Packet]:
    """Yield the packets recorded in ``path``.

    A **missing** file yields nothing: replaying a capture that was never taken is an
    empty result, not an error. A **corrupt** file raises :class:`OSError`, because a
    truncated capture must not be mistaken for a quiet network.
    """
    if not path.exists():
        logger.warning("capture file not found: %s", path)
        return
    if not _is_pcap(path):
        msg = f"not a pcap capture file: {path}"
        raise OSError(msg)
    reader = PcapReader(str(path))
    try:
        yield from reader
    except Scapy_Exception as exc:
        raise OSError(f"could not read capture file {path}: {exc}") from exc
    finally:
        reader.close()


class PcapSource:
    """Replays a recorded capture. Safe on any machine; needs no privileges."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    @property
    def description(self) -> str:
        return f"pcap:{self._path}"

    def __iter__(self) -> Iterator[Packet]:
        return iter_pcap(self._path)


class LiveSource:
    """Captures from a network interface using a background sniffer thread.

    Requires ``CAP_NET_RAW`` (and ``CAP_NET_ADMIN`` when promiscuous mode is needed).
    Those are granted to the sensor unit only — see ``deploy/systemd``.
    """

    def __init__(
        self,
        interface: str,
        bpf: str | None = DEFAULT_BPF,
        *,
        sniffer_factory: Callable[..., object] = AsyncSniffer,
    ) -> None:
        self._interface = interface
        self._bpf = bpf
        self._factory = sniffer_factory

    @property
    def description(self) -> str:
        return f"live:{self._interface}"

    def __iter__(self) -> Iterator[Packet]:
        packets: Queue[Packet] = Queue()
        # store=False keeps Scapy from retaining every packet it sees; prn hands each
        # one straight to the queue instead.
        sniffer = self._factory(
            iface=self._interface, filter=self._bpf, store=False, prn=packets.put
        )
        sniffer.start()  # type: ignore[attr-defined]
        try:
            while True:
                yield packets.get()
        finally:
            sniffer.stop()  # type: ignore[attr-defined]


def make_source(interface: str | None = None, path: Path | None = None) -> PacketSource:
    """Build a packet source from either an interface or a file path.

    Exactly one must be given. A path is preferred when both are supplied, so a
    configured replay still behaves like a replay.
    """
    if path is not None:
        return PcapSource(path)
    if interface:
        return LiveSource(interface)
    msg = "either interface or path must be provided"
    raise ValueError(msg)
