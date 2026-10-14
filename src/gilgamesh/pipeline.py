"""The event pipeline.

Every detection — from any sensor — passes through :class:`Pipeline` before it is
stored or announced. The brief's central requirement is that *one attack must not
produce thousands of alerts*, so the pipeline collapses repetition in five
bounded stages, applied in this order (decision D-012):

1. **dedup** — an event repeating within ``dedup_window`` for the same
   ``dedup_key`` is dropped outright. This absorbs packet-level bursts.
2. **cooldown** — an attack that has already raised an alert within ``cooldown``
   is not announced again. The owner already knows.
3. **per-key rate limit** — a sliding window per attack key, so one very chatty
   attack cannot monopolise attention even after the cooldown expires.
4. **global limit** — a ceiling on new alerts overall, protecting the box from a
   storm that uses many distinct keys (a scan sweeps thousands of addresses).
5. **incident aggregation** — surviving events fold into an open incident,
   incrementing its count instead of creating a new alert. Once the count
   reaches ``escalate_at`` the incident is re-announced at a higher severity.

The pipeline is pure: it returns a :class:`PipelineResult` and never touches the
database or the network. The caller decides what to do with the decision, which
keeps every stage testable in isolation and keeps a storage failure from being
mistaken for a detection result.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from gilgamesh.models import Event, Severity


class PipelineDecision(StrEnum):
    """What the pipeline decided to do with a submitted event."""

    #: A new incident: store the event and notify.
    STORE = "store"
    #: Folded into an open incident; increment its count, but do not notify.
    AGGREGATE = "aggregate"
    #: Identical repeat inside the dedup window.
    DEDUPED = "deduped"
    #: Already alerted for this attack recently.
    COOLDOWNED = "cooldowned"
    #: This key exceeded its own rate limit.
    RATE_LIMITED = "rate_limited"
    #: The global alert ceiling was reached.
    SUPPRESSED = "suppressed"


@dataclass(frozen=True, slots=True)
class PipelineSettings:
    """Tunable thresholds. Defaults come from decision D-012."""

    dedup_window: float = 5.0
    cooldown: float = 300.0
    rate_limit_count: int = 5
    rate_limit_window: float = 60.0
    aggregate_window: float = 900.0
    escalate_at: int = 50
    global_limit_count: int = 10
    global_limit_window: float = 60.0
    max_tracked_keys: int = 10_000


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Outcome of submitting one event."""

    decision: PipelineDecision
    incident_id: int | None = None
    count: int = 1
    severity: Severity | None = None


@dataclass(slots=True)
class _KeyState:
    """Per-attack state. Bounded by ``max_tracked_keys`` in :class:`Pipeline`."""

    last_seen: float | None = None
    last_alert: float | None = None
    hits: deque[float] = field(default_factory=lambda: deque[float]())
    incident_id: int | None = None
    incident_count: int = 0
    incident_last_seen: float = 0.0


class Pipeline:
    """Collapses repeated detections into a manageable number of alerts."""

    def __init__(
        self,
        settings: PipelineSettings | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._settings = settings if settings is not None else PipelineSettings()
        self._clock = clock if clock is not None else time.monotonic
        self._keys: OrderedDict[str, _KeyState] = OrderedDict()
        self._global: deque[float] = deque()
        self._next_incident_id = 1

    @property
    def tracked_key_count(self) -> int:
        """Number of attack keys currently held in memory."""
        return len(self._keys)

    def submit(self, event: Event) -> PipelineResult:
        """Run ``event`` through the pipeline and return the decision."""
        settings = self._settings
        now = self._clock()
        state = self._state_for(event.dedup_key)

        if state.last_seen is not None and now - state.last_seen < settings.dedup_window:
            return PipelineResult(PipelineDecision.DEDUPED)
        state.last_seen = now

        if state.last_alert is not None and now - state.last_alert < settings.cooldown:
            return PipelineResult(PipelineDecision.COOLDOWNED)

        if not self._within_rate_limit(state, now):
            return PipelineResult(PipelineDecision.RATE_LIMITED)

        if not self._within_global_limit(now):
            return PipelineResult(PipelineDecision.SUPPRESSED)

        return self._aggregate_or_open(state, event, now)

    def _state_for(self, key: str) -> _KeyState:
        """Return the state for ``key``, evicting least-recently-used keys."""
        state = self._keys.get(key)
        if state is None:
            state = _KeyState()
            self._keys[key] = state
            max_keys = self._settings.max_tracked_keys
            while len(self._keys) > max_keys:
                self._keys.popitem(last=False)
        else:
            self._keys.move_to_end(key)
        return state

    def _within_rate_limit(self, state: _KeyState, now: float) -> bool:
        """Consume one slot from this key's sliding window if one is available."""
        limit = self._settings.rate_limit_count
        if limit <= 0:
            return True
        window = self._settings.rate_limit_window
        while state.hits and now - state.hits[0] >= window:
            state.hits.popleft()
        if len(state.hits) >= limit:
            return False
        state.hits.append(now)
        return True

    def _within_global_limit(self, now: float) -> bool:
        """Consume one slot from the global sliding window if one is available."""
        limit = self._settings.global_limit_count
        if limit <= 0:
            return True
        window = self._settings.global_limit_window
        while self._global and now - self._global[0] >= window:
            self._global.popleft()
        if len(self._global) >= limit:
            return False
        self._global.append(now)
        return True

    def _aggregate_or_open(self, state: _KeyState, event: Event, now: float) -> PipelineResult:
        """Fold the event into an open incident, or open a new one."""
        window = self._settings.aggregate_window
        if state.incident_id is not None and now - state.incident_last_seen < window:
            state.incident_count += 1
            state.incident_last_seen = now
            if state.incident_count >= self._settings.escalate_at:
                # Sustained attack: re-announce once, at a higher severity.
                state.last_alert = now
                return PipelineResult(
                    PipelineDecision.STORE,
                    state.incident_id,
                    state.incident_count,
                    event.severity.escalated(),
                )
            return PipelineResult(
                PipelineDecision.AGGREGATE,
                state.incident_id,
                state.incident_count,
                event.severity,
            )

        state.incident_id = self._next_incident_id
        self._next_incident_id += 1
        state.incident_count = 1
        state.incident_last_seen = now
        state.last_alert = now
        return PipelineResult(PipelineDecision.STORE, state.incident_id, 1, event.severity)
