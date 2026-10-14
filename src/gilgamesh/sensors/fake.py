"""A stand-in detector used to prove the pipeline works end to end.

**This detector detects nothing.** It fabricates one synthetic event so the first
milestone can prove the path *detector → database → web UI* is wired correctly
before any real detection logic exists. It is replaced by the real detectors
(ARP, DNS, DHCP, scan/flood, inventory) as they are implemented.
"""

from __future__ import annotations

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.base import Detector


class FakeDetector(Detector):
    """Emits a single, obviously-synthetic informational event."""

    name = "fake"

    def events(self) -> list[Event]:
        return [
            Event(
                type=EventType.TEST,
                severity=Severity.INFO,
                detector=self.name,
                summary="hello gilgamesh",
                details={"note": "synthetic event from the walking-skeleton detector"},
            )
        ]
