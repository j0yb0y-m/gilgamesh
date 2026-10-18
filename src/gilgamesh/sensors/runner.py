"""Sensor process entrypoint.

The runner owns the capture loop and is the only place that knows whether packets came
from a wire or a file. For every packet it:

1. offers it to each detector, in isolation, so one broken detector cannot stop the rest;
2. pushes whatever events come back through the pipeline, which decides what is worth
   storing and announcing;
3. stores the surviving events.

**Why the capture loop is here and not in the web app.** Capture needs
``CAP_NET_RAW``; the web app must not have it (decision D-019). Splitting the two into
separate processes, communicating through SQLite in WAL mode, means a compromise of the
web tier cannot read the network and a fault in the web tier cannot stop detection.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from scapy.packet import Packet

from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event
from gilgamesh.pipeline import Pipeline, PipelineDecision
from gilgamesh.sensors.base import PacketDetector
from gilgamesh.sensors.capture import DEFAULT_BPF, PacketSource, make_source
from gilgamesh.sensors.inventory import is_randomised_mac, observe_device

logger = logging.getLogger(__name__)

#: How long a device's ``last_seen`` may go un-refreshed while the box is busy. A packet
#: is not a reason to write to SQLite, but the Devices page must not show a stale "seen"
#: time either, so a repeat sighting refreshes the row at most this often.
DEVICE_REFRESH_SECONDS = 60.0


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
        self._clock = clock if clock is not None else time.monotonic
        self._device_refreshed: dict[str, float] = {}
        self._processed = 0

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

    def run_forever(self) -> None:
        """Process packets until interrupted. Used by ``gilgamesh-sensor.service``."""
        for packet in self._build_source():
            self._handle(packet)
            self._processed += 1

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
                self._submit(event)

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

    def _submit(self, event: Event) -> None:
        """Pass an event to the pipeline and store it if it survives."""
        result = self._pipeline.submit(self._stamped(event))
        if result.decision is not PipelineDecision.STORE:
            logger.debug(
                "pipeline dropped %s from %s: %s", event.summary, event.detector, result.decision
            )
            return
        self._database.insert_event(self._stamped(event))
        logger.info("stored %s event from %s: %s", event.severity, event.detector, event.summary)

    def _stamped(self, event: Event) -> Event:
        """Attach the capture interface to an event that does not already name one.

        The runner knows where the packet came from; the detector does not, so this is
        the only place the interface can be recorded reliably.
        """
        label = self._config.label
        if label is None or event.interface is not None:
            return event
        return event.model_copy(update={"interface": label})


def main() -> None:
    """Entry point for ``gilgamesh-sensor`` service."""
    import logging
    import signal
    import sys
    from threading import Event

    from gilgamesh.config import Settings
    from gilgamesh.db import Database
    from gilgamesh.devices import DeviceStore
    from gilgamesh.pipeline import Pipeline
    from gilgamesh.rules import RuleConfigService, default_catalogue
    from gilgamesh.sensors.arp import ArpConfig, ArpDetector
    from gilgamesh.sensors.dhcp import DhcpConfig, DhcpDetector
    from gilgamesh.sensors.dns import DnsConfig, DnsDetector
    from gilgamesh.sensors.inventory import InventoryConfig, InventoryDetector
    from gilgamesh.sensors.scan_flood import ScanConfig, ScanDetector
    from gilgamesh.web.auth import create_auth_service

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    settings = Settings()
    db = Database(settings.db_path)
    db.initialize()

    device_store = DeviceStore(db)
    _auth = create_auth_service(db)
    _rules = RuleConfigService(db, default_catalogue())
    _prefs = None

    pipeline = Pipeline()
    detectors: list[PacketDetector] = [
        ArpDetector(ArpConfig(gateway_ip="127.0.0.1")),
        InventoryDetector(InventoryConfig()),
        DhcpDetector(DhcpConfig()),
        DnsDetector(DnsConfig()),
        ScanDetector(ScanConfig()),
    ]
    config = SensorRunnerConfig(interface=None)  # will be configured via env/settings in deployment
    runner = SensorRunner(detectors, db, pipeline, config, device_store=device_store)

    stop = Event()

    def _handle_signal(signum: int, frame: object) -> None:
        del signum, frame
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _handle_signal)  # type: ignore[no-untyped-call]

    try:
        while not stop.is_set():
            runner.run_once()
    finally:
        db.close()
        sys.exit(0)


__all__ = ["DEVICE_REFRESH_SECONDS", "SensorRunner", "SensorRunnerConfig", "main"]
