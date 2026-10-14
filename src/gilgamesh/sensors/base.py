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
