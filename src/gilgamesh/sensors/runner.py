"""Sensor process entrypoint.

The runner owns the capture loop and is the only place that knows whether packets came
from a wire or a file. For every packet it:

1. offers it to each detector, in isolation, so one broken detector cannot stop the rest;
2. asks the :class:`~gilgamesh.sensors.gate.RuleGate` whether the owner wants to be told
   (rule switches, allowlists, trusted devices);
3. pushes whatever comes back through the pipeline, which decides what is worth storing
   and announcing;
4. stores the surviving events — at the severity the pipeline decided, so a re-announced
   incident is stored at its escalated severity.

**Why the capture loop is here and not in the web app.** Capture needs
``CAP_NET_RAW``; the web app must not have it (decision D-019). Splitting the two into
separate processes, communicating through SQLite in WAL mode, means a compromise of the
web tier cannot read the network and a fault in the web tier cannot stop detection.

**How it is configured.** Interface, optional PCAP replay, optional gateway address and
the optional Suricata EVE log all come from :class:`gilgamesh.config.Settings`
(environment, ``deploy/gilgamesh.env``), while the owner's detection choices come from
the database — the same rows the Rules and Allowlist pages write. Starting with neither
an interface nor a PCAP is a configuration error and exits non-zero: a sensor that
silently does nothing is worse than one that refuses to start.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Event as ThreadEvent
from threading import Lock, Thread
from types import FrameType

from scapy.packet import Packet

from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event
from gilgamesh.pipeline import Pipeline, PipelineDecision
from gilgamesh.rules import RuleConfigService
from gilgamesh.sensors.base import PacketDetector
from gilgamesh.sensors.capture import DEFAULT_BPF, PacketSource, make_source
from gilgamesh.sensors.gate import RuleGate
from gilgamesh.sensors.inventory import is_randomised_mac, observe_device

logger = logging.getLogger(__name__)

#: How long a device's ``last_seen`` may go un-refreshed while the box is busy. A packet
#: is not a reason to write to SQLite, but the Devices page must not show a stale "seen"
#: time either, so a repeat sighting refreshes the row at most this often.
DEVICE_REFRESH_SECONDS = 60.0

#: Where Linux exposes the routing table the gateway lookup reads.
PROC_ROUTE = Path("/proc/net/route")

#: ``dns.spoofing``'s sensitivity scales the conflicting-answer threshold: strict
#: halves it (more alerts), relaxed doubles it (fewer), balanced is the stored value.
_SENSITIVITY_FACTORS = {"relaxed": 2.0, "balanced": 1.0, "strict": 0.5}


@dataclass(frozen=True, slots=True)
class SensorRunnerConfig:
    """Where to capture from, and how to label what came out."""

    #: Replay a recorded capture instead of a live interface.
    source: Path | None = None
    #: Live interface to capture from when ``source`` is not set.
    interface: str | None = None
    bpf: str | None = DEFAULT_BPF
    #: Recorded on every event, so the UI can show where something was seen.
    interface_label: str | None = None

    @property
    def label(self) -> str | None:
        """Interface name to stamp on events: the explicit label, else the interface."""
        return self.interface_label if self.interface_label is not None else self.interface


class SensorRunner:
    """Drives detectors over a packet source and persists what they find."""

    def __init__(
        self,
        detectors: Sequence[PacketDetector],
        database: Database,
        pipeline: Pipeline,
        config: SensorRunnerConfig | None = None,
        *,
        device_store: DeviceStore | None = None,
        gate: RuleGate | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._detectors = list(detectors)
        self._database = database
        self._pipeline = pipeline
        self._config = config if config is not None else SensorRunnerConfig()
        #: When set, every observed device is mirrored into the inventory table so the web
        #: tier (a different process) can render the Devices page. Optional so the runner
        #: stays usable in tests that only care about detectors.
        self._device_store = device_store
        #: When set, events are filtered through the owner's rule settings before the
        #: pipeline sees them. Optional for the same reason as the device store.
        self._gate = gate
        self._clock = clock if clock is not None else time.monotonic
        self._device_refreshed: dict[str, float] = {}
        self._processed = 0
        #: The pipeline is stateful and the Suricata tailer is a second thread, so every
        #: submission is serialised here rather than mutating its state concurrently.
        self._submit_lock = Lock()

    @property
    def packets_processed(self) -> int:
        """Number of packets fed to the detectors since start-up."""
        return self._processed

    def run_once(self) -> int:
        """Process every packet the source yields, then return.

        Used for replaying a capture — in tests, and by the offline analysis command.
        """
        processed = 0
        for packet in self._build_source():
            self._handle(packet)
            processed += 1
        self._processed += processed
        return processed

    def run_forever(self, stop: ThreadEvent | None = None) -> int:
        """Process packets until ``stop`` is set, returning how many were handled.

        With ``stop`` unset this never returns for a live source. ``stop`` is checked
        between packets; a signal handler that raises is what interrupts the blocking
        read of a live source (see :func:`main`).
        """
        processed = 0
        for packet in self._build_source():
            if stop is not None and stop.is_set():
                break
            self._handle(packet)
            self._processed += 1
            processed += 1
        return processed

    def _build_source(self) -> PacketSource:
        return make_source(
            interface=self._config.interface,
            path=self._config.source,
        )

    def _handle(self, packet: Packet) -> None:
        """Run one packet through every detector, then the pipeline, then storage."""
        self._record_device(packet)
        for detector in self._detectors:
            try:
                events = detector.process(packet)
            except Exception:
                logger.exception("detector %s failed on a packet", detector.name)
                continue
            for event in events:
                self.submit_event(event)

    def _record_device(self, packet: Packet) -> None:
        """Mirror a sighting into the device inventory, at most once per refresh window.

        The detectors keep the authoritative in-memory view; this is only so the web
        process can see the same devices. Writes are throttled because there is one
        packet per write otherwise, which a Pi's SD card will not thank us for.
        """
        if self._device_store is None:
            return
        observed = observe_device(packet)
        if observed is None:
            return
        now = self._clock()
        last = self._device_refreshed.get(observed.mac)
        if last is not None and now - last < DEVICE_REFRESH_SECONDS:
            return
        self._device_refreshed[observed.mac] = now
        try:
            self._device_store.upsert(
                observed.mac,
                ip=observed.ip,
                hostname=observed.hostname,
                randomised=is_randomised_mac(observed.mac),
            )
        except ValueError:
            # A malformed address is not worth stopping capture for.
            logger.debug("ignoring device with unparseable address")
        except Exception:
            logger.exception("failed to record device %s", observed.mac)

    def submit_event(self, event: Event) -> bool:
        """Gate, pipeline, and store one event; returns whether it was stored.

        Public because the Suricata tailer thread is a second event source feeding the
        same gate and pipeline as the packet path. The lock keeps the pipeline's state
        consistent between the two threads.
        """
        with self._submit_lock:
            stamped = self._stamped(event)
            if self._gate is not None and not self._gate.allows(stamped):
                logger.debug("rule settings dropped %s from %s", stamped.summary, stamped.detector)
                return False
            result = self._pipeline.submit(stamped)
            if result.decision is not PipelineDecision.STORE:
                logger.debug(
                    "pipeline dropped %s from %s: %s",
                    stamped.summary,
                    stamped.detector,
                    result.decision,
                )
                return False
            stored = stamped
            if result.severity is not None and result.severity is not stamped.severity:
                # A re-announced incident stores the escalated severity; storing the
                # original would silently understate what the owner is being told.
                stored = stamped.model_copy(update={"severity": result.severity})
            self._database.insert_event(stored)
            logger.info(
                "stored %s event from %s: %s", stored.severity, stored.detector, stored.summary
            )
            return True

    def _stamped(self, event: Event) -> Event:
        """Attach the capture interface to an event that does not already name one.

        The runner knows where the packet came from; the detector does not, so this is
        the only place the interface can be recorded reliably.
        """
        label = self._config.label
        if label is None or event.interface is not None:
            return event
        return event.model_copy(update={"interface": label})


def detect_default_gateway(route_file: Path = PROC_ROUTE) -> str | None:
    """The default gateway from the kernel routing table, or ``None``.

    The ARP detector needs to know which address is the gateway to protect its binding.
    The address is a property of the host the sensor runs on, so it is read here rather
    than typed in by the owner. Linux only; on any other platform — or a routing table
    without a default route — the answer is ``None`` and the gateway check stays off,
    while the detector's other checks continue to work.
    """
    try:
        lines = route_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 3 or fields[1] != "00000000":
            continue
        try:
            raw = int(fields[2], 16)
        except ValueError:
            continue
        try:
            octets = raw.to_bytes(4, "little")
        except OverflowError:
            continue
        return ".".join(str(octet) for octet in octets)
    return None


def _param(
    rules: RuleConfigService, rule_id: str, name: str, cast: type[int] | type[float]
) -> float:
    """One stored parameter as a number, falling back to the catalogue default.

    The Rules page validates what it writes, but a damaged row (hand edit, interrupted
    write) must not stop the sensor from starting: an unusable value degrades to the
    shipped default and is logged, which keeps detection running with sane thresholds.
    """
    definition = rules.catalogue.require(rule_id)
    fallback = definition.defaults()[name]
    raw = rules.effective_params(rule_id).get(name, fallback)
    try:
        return float(cast(raw))
    except (TypeError, ValueError):
        logger.warning(
            "rule %s has an unusable %s (%r); using the default %r", rule_id, name, raw, fallback
        )
        return float(cast(fallback))


def _int_param(rules: RuleConfigService, rule_id: str, name: str) -> int:
    return round(_param(rules, rule_id, name, int))


def _float_param(rules: RuleConfigService, rule_id: str, name: str) -> float:
    return _param(rules, rule_id, name, float)


def build_detectors(
    rules: RuleConfigService,
    *,
    gateway_ip: str | None,
    interface: str | None,
) -> list[PacketDetector]:
    """Build one instance of each detector from the owner's stored parameters.

    Parameter names differ between the catalogue (owner-facing) and the detector
    configs (internal), and this function is the single translation between them. Two
    details worth knowing:

    * the scan detector keeps one window for both scans, so ``scan.vertical``'s value
      is the one used;
    * ``dns.spoofing``'s ``sensitivity`` scales the conflicting-answer threshold —
      ``strict`` halves it, ``relaxed`` doubles it, ``balanced`` stores it unchanged.
    """
    from gilgamesh.sensors.arp import ArpConfig, ArpDetector
    from gilgamesh.sensors.dhcp import DhcpConfig, DhcpDetector
    from gilgamesh.sensors.dns import DnsConfig, DnsDetector
    from gilgamesh.sensors.inventory import InventoryConfig, InventoryDetector
    from gilgamesh.sensors.scan_flood import ScanConfig, ScanDetector

    sensitivity = str(rules.effective_params("dns.spoofing").get("sensitivity", "balanced"))
    factor = _SENSITIVITY_FACTORS.get(sensitivity, 1.0)
    conflict_threshold = max(
        2, round(_int_param(rules, "dns.spoofing", "conflict_threshold") * factor)
    )

    return [
        ArpDetector(
            ArpConfig(
                gateway_ip=gateway_ip,
                garp_burst_threshold=_int_param(rules, "arp.gratuitous_flood", "burst_threshold"),
                garp_window_seconds=_float_param(rules, "arp.gratuitous_flood", "window"),
                interface=interface,
            )
        ),
        DnsDetector(
            DnsConfig(
                conflict_threshold=conflict_threshold,
                no_match_window_seconds=_float_param(rules, "dns.spoofing", "no_match_window"),
                interface=interface,
            )
        ),
        DhcpDetector(
            DhcpConfig(
                discover_rate_threshold=_int_param(rules, "dhcp.starvation", "discover_threshold"),
                distinct_clients_threshold=_int_param(rules, "dhcp.starvation", "distinct_clients"),
                starvation_window=_float_param(rules, "dhcp.starvation", "window"),
                interface=interface,
            )
        ),
        ScanDetector(
            ScanConfig(
                vertical_threshold=_int_param(rules, "scan.vertical", "port_threshold"),
                horizontal_threshold=_int_param(rules, "scan.horizontal", "host_threshold"),
                scan_window=_float_param(rules, "scan.vertical", "scan_window"),
                syn_flood_threshold=_int_param(rules, "scan.syn_flood", "syn_threshold"),
                syn_flood_window=_float_param(rules, "scan.syn_flood", "syn_window"),
                interface=interface,
            )
        ),
        InventoryDetector(
            InventoryConfig(
                learning_seconds=_float_param(rules, "inventory.new_device", "learning_seconds"),
                interface=interface,
            )
        ),
    ]


def _start_suricata_tailer(
    path: Path | None, runner: SensorRunner, stop: ThreadEvent
) -> Thread | None:
    """Follow Suricata's EVE log in a background thread, if one is configured.

    Suricata is an optional second opinion: its alerts enter through the same gate and
    pipeline as the custom detectors, so one attack still produces one alert. A missing
    or unreadable log kills only this thread — the custom detectors keep running, which
    is the fail-safe direction.
    """
    if path is None:
        return None

    from gilgamesh.sensors.suricata_ingest import EveIngestor

    ingestor = EveIngestor()

    def _tail() -> None:
        logger.info("tailing Suricata EVE log at %s", path)
        try:
            for event in ingestor.follow(path, stop):
                runner.submit_event(event)
        except Exception:
            logger.exception("Suricata tailer stopped; the custom detectors keep running")

    thread = Thread(target=_tail, name="suricata-eve", daemon=True)
    thread.start()
    return thread


def main() -> None:
    """Entry point for the ``gilgamesh-sensor`` service."""
    import signal
    import sys

    from gilgamesh.config import Settings
    from gilgamesh.rules import default_catalogue
    from gilgamesh.util.logging import configure_logging

    configure_logging()

    settings = Settings()
    if settings.pcap is not None:
        source_label = f"pcap file {settings.pcap}"
    elif settings.interface:
        source_label = f"interface {settings.interface}"
    else:
        logger.error(
            "no capture source configured: set GILGAMESH_INTERFACE for live capture or "
            "GILGAMESH_PCAP to replay a file (see deploy/gilgamesh.env)"
        )
        raise SystemExit(2)

    try:
        db = Database(settings.db_path)
        db.initialize()
    except Exception:
        logger.exception(
            "cannot open the database at %s; check GILGAMESH_DATA_DIR and permissions",
            settings.db_path,
        )
        raise SystemExit(2) from None

    rules = RuleConfigService(db, default_catalogue())
    device_store = DeviceStore(db)
    gate = RuleGate(rules, device_store)
    gateway_ip = settings.gateway_ip or detect_default_gateway()
    if gateway_ip is None:
        logger.warning(
            "no gateway address found (set GILGAMESH_GATEWAY_IP); "
            "the ARP gateway-MAC check is disabled, the other ARP checks still run"
        )
    detectors = build_detectors(rules, gateway_ip=gateway_ip, interface=settings.interface)
    config = SensorRunnerConfig(
        source=settings.pcap,
        interface=settings.interface,
        interface_label=settings.interface,
    )
    runner = SensorRunner(detectors, db, Pipeline(), config, device_store=device_store, gate=gate)

    stop = ThreadEvent()

    def _handle_signal(signum: int, _frame: FrameType | None) -> None:
        # Setting the flag alone would not interrupt a live capture blocked on its
        # packet queue (PEP 475 retries the interrupted syscall), so the handler also
        # unwinds the loop — which runs the ``finally`` below and closes the database.
        logger.info("received %s; shutting down", signal.Signals(signum).name)
        stop.set()
        raise SystemExit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _handle_signal)

    tailer = _start_suricata_tailer(settings.suricata_eve_path, runner, stop)
    mode = "replay" if settings.pcap is not None else "live"
    logger.info("sensor started: %s capture from %s", mode, source_label)

    try:
        processed = runner.run_forever(stop)
        if settings.pcap is not None:
            logger.info("replay finished: %d packets processed", processed)
    finally:
        stop.set()
        if tailer is not None:
            tailer.join(timeout=2.0)
        db.close()
        if settings.pcap is None:
            logger.info("sensor stopped after %d packets", runner.packets_processed)

    sys.exit(0)


__all__ = [
    "DEVICE_REFRESH_SECONDS",
    "PROC_ROUTE",
    "SensorRunner",
    "SensorRunnerConfig",
    "build_detectors",
    "detect_default_gateway",
    "main",
]
