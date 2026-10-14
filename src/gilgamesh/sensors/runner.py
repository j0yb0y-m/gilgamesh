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
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from scapy.packet import Packet

from gilgamesh.db import Database
from gilgamesh.models import Event
from gilgamesh.pipeline import Pipeline, PipelineDecision
from gilgamesh.sensors.base import PacketDetector
from gilgamesh.sensors.capture import DEFAULT_BPF, PacketSource, make_source

logger = logging.getLogger(__name__)


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
    ) -> None:
        self._detectors = list(detectors)
        self._database = database
        self._pipeline = pipeline
        self._config = config if config is not None else SensorRunnerConfig()
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
        for detector in self._detectors:
            try:
                events = detector.process(packet)
            except Exception:
                logger.exception("detector %s failed on a packet", detector.name)
                continue
            for event in events:
                self._submit(event)

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
