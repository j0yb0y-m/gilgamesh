"""Run behaviour aggregation in the sensor process.

The service owns the EVE follower, the bounded queue between the follower and the
aggregator, the periodic status publish, and the disable/re-enable loop. It never
touches the capture path: if Suricata's log is missing or the behaviour engine
fails, the custom detectors keep running.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from queue import Empty, Queue
from threading import Event as ThreadEvent
from threading import Thread
from time import monotonic
from typing import Protocol, cast

from gilgamesh.behaviour.aggregate import BehaviourAggregator, BehaviourParams
from gilgamesh.behaviour.attribution import DeviceMap
from gilgamesh.behaviour.eve import DnsFact, FlowFact, parse_behaviour_record
from gilgamesh.behaviour.store import BehaviourStatus, BehaviourStore
from gilgamesh.db import Database
from gilgamesh.devices import DeviceStore
from gilgamesh.models import Event
from gilgamesh.preferences import PreferencesStore
from gilgamesh.rules import RuleConfigService
from gilgamesh.sensors.eve_tail import follow_json_lines

logger = logging.getLogger(__name__)

#: ``app_settings`` prefix for the behaviour reader's own EVE position.
POSITION_KEY_PREFIX = "behaviour_eve_position:"

#: The producer blocks when this fills; a full queue means the consumer is behind,
#: which is preferable to unbounded memory on a 4 GB Pi.
QUEUE_MAXSIZE = 10_000

_SENTINEL = object()

FollowerFactory = Callable[[Path, Database, str, ThreadEvent], Iterator[dict[str, object]]]
Clock = Callable[[], datetime]


class Aggregator(Protocol):
    """The aggregator surface the service drives (real or injected in tests)."""

    @property
    def status(self) -> BehaviourStatus: ...

    def record(self, fact: FlowFact | DnsFact) -> None: ...

    def flush(self, now: datetime | None = None) -> list[Event]: ...

    def close(self) -> list[Event]: ...


AggregatorFactory = Callable[[BehaviourStore, DeviceMap], Aggregator]


class EventSink(Protocol):
    """The part of :class:`~gilgamesh.sensors.runner.SensorRunner` the service needs."""

    def submit_event(self, event: Event) -> bool: ...


class BehaviourService:
    """Follow EVE, aggregate flow/DNS facts, and publish status."""

    STATUS_INTERVAL_SECONDS = 10.0
    PREFERENCE_CHECK_SECONDS = 5.0
    DISABLE_RETRY_SECONDS = 5.0
    DEVICE_REFRESH_SECONDS = 60.0

    def __init__(
        self,
        database: Database,
        device_store: DeviceStore,
        preferences: PreferencesStore,
        *,
        eve_path: Path | None,
        submit_event: Callable[[Event], bool],
        rules: RuleConfigService | None = None,
        clock: Clock | None = None,
        follower_factory: FollowerFactory | None = None,
        aggregator_factory: AggregatorFactory | None = None,
    ) -> None:
        self._database = database
        self._device_store = device_store
        self._preferences = preferences
        self._eve_path = eve_path
        self._submit_event = submit_event
        self._rules = rules
        self._clock = clock or (lambda: datetime.now(UTC))
        self._follower_factory = follower_factory or _follow
        self._store = BehaviourStore(database)
        self._devices = DeviceMap()
        factory = aggregator_factory or self._default_aggregator_factory
        self._aggregator = factory(self._store, self._devices)
        self._parse_errors = 0

    def run_once(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        now: datetime | None = None,
    ) -> list[Event]:
        """Consume a finite batch, write finalized buckets, and return any events."""
        if not self._preferences.get().behaviour_enabled:
            self._publish(enabled=False)
            return []

        self._refresh_devices()
        for record in records:
            self._consume(record)
        events = self._aggregator.flush(now=now or self._clock())
        for event in events:
            self._submit_event(event)
        self._publish(enabled=True)
        return events

    def run(self, stop: ThreadEvent) -> None:
        """Follow EVE until ``stop`` is set, honoring the enabled preference."""
        if self._eve_path is None:
            self._publish(enabled=self._preferences.get().behaviour_enabled)
            return

        while not stop.is_set():
            if not self._preferences.get().behaviour_enabled:
                self._publish(enabled=False)
                if stop.wait(self.DISABLE_RETRY_SECONDS):
                    return
                continue

            self._tail(stop)
            if stop.is_set():
                return
            if stop.wait(self.DISABLE_RETRY_SECONDS):
                return

        self._publish(enabled=self._preferences.get().behaviour_enabled)

    def _default_aggregator_factory(
        self, store: BehaviourStore, devices: DeviceMap
    ) -> BehaviourAggregator:
        return BehaviourAggregator(
            store,
            devices,
            calibration_days=self._preferences.get().behaviour_calibration_days,
            params=BehaviourParams.from_rules(self._rules) if self._rules is not None else None,
        )

    def _tail(self, stop: ThreadEvent) -> None:
        """One tail session: producer reads, consumer aggregates, disable ends it."""
        path = self._eve_path
        if path is None:
            raise RuntimeError("behaviour tail started without an EVE path")
        queue: Queue[object] = Queue(maxsize=QUEUE_MAXSIZE)
        producer_stop = ThreadEvent()
        position_key = f"{POSITION_KEY_PREFIX}{path}"

        def _produce() -> None:
            try:
                for record in self._follower_factory(
                    path, self._database, position_key, producer_stop
                ):
                    queue.put(record)
            except Exception:
                logger.exception("behaviour EVE follower stopped; retrying")
            finally:
                queue.put(_SENTINEL)

        producer = Thread(target=_produce, name="behaviour-eve", daemon=True)
        producer.start()
        self._refresh_devices()
        last_status = last_preference = last_refresh = monotonic()

        try:
            while not stop.is_set() and self._preferences.get().behaviour_enabled:
                try:
                    item = queue.get(timeout=1.0)
                except Empty:
                    item = None

                if item is _SENTINEL:
                    break
                if item is not None:
                    self._consume(cast("Mapping[str, object]", item))

                moment = monotonic()
                if moment - last_status >= self.STATUS_INTERVAL_SECONDS:
                    self._publish()
                    last_status = moment
                if moment - last_preference >= self.PREFERENCE_CHECK_SECONDS:
                    last_preference = moment
                if moment - last_refresh >= self.DEVICE_REFRESH_SECONDS:
                    self._refresh_devices()
                    last_refresh = moment
        finally:
            producer_stop.set()
            self._drain(queue, producer, process=stop.is_set())
            producer.join(timeout=2.0)

            if stop.is_set():
                self._finish()
            elif not self._preferences.get().behaviour_enabled:
                self._publish(enabled=False)
            else:
                for event in self._aggregator.flush(now=self._clock()):
                    self._submit_event(event)
                self._publish()

    def _drain(self, queue: Queue[object], producer: Thread, *, process: bool) -> None:
        """Empty the queue until the producer has finished.

        On shutdown the drained records are still aggregated; on disable they are
        discarded, because disabled means "do not write activity". Either way the
        producer must be allowed to unblock from a full queue.
        """
        while True:
            try:
                item = queue.get(timeout=0.5)
            except Empty:
                if not producer.is_alive():
                    return
                continue
            if item is _SENTINEL:
                return
            if process:
                self._consume(cast("Mapping[str, object]", item))

    def _finish(self) -> None:
        for event in self._aggregator.close():
            self._submit_event(event)
        self._publish()

    def _consume(self, record: Mapping[str, object]) -> None:
        kind = record.get("event_type")
        if kind not in ("flow", "dns"):
            return
        fact = parse_behaviour_record(record)
        if fact is None:
            self._parse_errors += 1
            return
        try:
            self._aggregator.record(fact)
        except Exception:
            logger.exception("behaviour aggregator rejected one record")
            self._parse_errors += 1

    def _refresh_devices(self) -> None:
        self._devices.refresh(self._device_store.list())

    def _publish(self, *, enabled: bool | None = None) -> None:
        available = self._eve_path is not None and self._eve_path.exists()
        status = self._aggregator.status.model_copy(
            update={
                "parse_errors": self._parse_errors,
                "enabled": (
                    self._preferences.get().behaviour_enabled if enabled is None else enabled
                ),
                "suricata_available": available,
            }
        )
        self._store.write_status(status)


def _follow(
    path: Path, database: Database, position_key: str, stop: ThreadEvent
) -> Iterator[dict[str, object]]:
    return follow_json_lines(path, database=database, position_key=position_key, stop=stop)


def start_behaviour_service(
    path: Path | None,
    runner: EventSink,
    stop: ThreadEvent,
    database: Database,
    device_store: DeviceStore,
    preferences: PreferencesStore,
    rules: RuleConfigService | None = None,
) -> Thread | None:
    """Start the behaviour thread when Suricata's EVE log is configured."""
    if path is None:
        return None
    service = BehaviourService(
        database,
        device_store,
        preferences,
        eve_path=path,
        submit_event=runner.submit_event,
        rules=rules,
    )
    thread = Thread(target=service.run, args=(stop,), name="behaviour", daemon=True)
    thread.start()
    return thread


__all__ = [
    "POSITION_KEY_PREFIX",
    "QUEUE_MAXSIZE",
    "BehaviourService",
    "BehaviourStatus",
    "start_behaviour_service",
]
