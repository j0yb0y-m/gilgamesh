"""Common interface for every detector.

A detector turns an observation into zero or more normalized
:class:`~gilgamesh.models.Event` objects. Detectors know nothing about
storage, deduplication, or notification — they only report what they saw.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from gilgamesh.models import Event


class Detector(ABC):
    """Base class for detectors."""

    #: Short, stable identifier recorded on every event it emits.
    name: str

    @abstractmethod
    def events(self) -> list[Event]:
        """Return the events produced from the most recent observation.

        Returns an empty list when nothing was detected.
        """


class PacketDetector(Detector):
    """A detector driven by captured packets.

    Separated from :class:`Detector` because the sensor runner can only feed something
    that consumes packets, and typing it explicitly keeps that contract honest rather
    than relying on a duck-typed attribute that may not exist.
    """

    @abstractmethod
    def process(self, packet: object) -> list[Event]:
        """Inspect one captured packet and return the events it triggered.

        Must never raise for ordinary malformed traffic; return an empty list instead.
        Returns an empty list when nothing was detected.
        """
