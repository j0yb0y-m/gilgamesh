"""M2 — event pipeline tests.

The pipeline is what guarantees the brief's central requirement: *one attack must
not produce thousands of alerts*. Stages, in order (decision D-012):

    dedup → cooldown → per-key rate limit → global limit → incident aggregation

A ``Clock`` is injected so time-based behaviour is tested deterministically instead
of with sleeps.
"""

from __future__ import annotations

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.pipeline import Pipeline, PipelineDecision, PipelineSettings


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self._now = 0.0

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def make_event(
    *,
    detector: str = "arp",
    src_ip: str = "10.0.0.2",
    dst_ip: str = "10.0.0.1",
    severity: Severity = Severity.HIGH,
) -> Event:
    """Build an event whose ``dedup_key`` is derived from detector/type/src/dst."""
    return Event(
        type=EventType.ARP_SPOOF,
        severity=severity,
        detector=detector,
        summary="spoofed binding",
        src_ip=src_ip,
        dst_ip=dst_ip,
    )


def make_pipeline(**overrides: object) -> tuple[Pipeline, FakeClock]:
    """Build a pipeline with a fake clock and the given setting overrides."""
    clock = FakeClock()
    settings = PipelineSettings(**overrides)  # type: ignore[arg-type]
    return Pipeline(settings=settings, clock=clock.now), clock


def test_first_event_is_stored_as_a_new_incident() -> None:
    pipeline, _ = make_pipeline()

    result = pipeline.submit(make_event())

    assert result.decision is PipelineDecision.STORE
    assert result.incident_id is not None
    assert result.count == 1


def test_identical_event_inside_dedup_window_is_deduplicated() -> None:
    pipeline, clock = make_pipeline(dedup_window=5.0)
    event = make_event()

    assert pipeline.submit(event).decision is PipelineDecision.STORE
    clock.advance(2.0)
    assert pipeline.submit(event).decision is PipelineDecision.DEDUPED


def test_same_attack_after_dedup_window_is_cooled_down() -> None:
    pipeline, clock = make_pipeline(dedup_window=5.0, cooldown=300.0)
    event = make_event()

    assert pipeline.submit(event).decision is PipelineDecision.STORE
    clock.advance(10.0)
    assert pipeline.submit(event).decision is PipelineDecision.COOLDOWNED


def test_per_key_rate_limit_applies() -> None:
    pipeline, clock = make_pipeline(
        dedup_window=0.0,
        cooldown=0.0,
        aggregate_window=0.0,
        rate_limit_count=2,
        rate_limit_window=60.0,
    )
    event = make_event()

    assert pipeline.submit(event).decision is PipelineDecision.STORE
    clock.advance(1.0)
    assert pipeline.submit(event).decision is PipelineDecision.STORE
    clock.advance(1.0)
    assert pipeline.submit(event).decision is PipelineDecision.RATE_LIMITED


def test_global_limiter_caps_alerts_across_keys() -> None:
    pipeline, _ = make_pipeline(
        dedup_window=0.0,
        cooldown=0.0,
        aggregate_window=0.0,
        rate_limit_count=100,
        global_limit_count=3,
    )

    decisions = [pipeline.submit(make_event(src_ip=f"10.0.0.{i}")).decision for i in range(5)]

    assert decisions.count(PipelineDecision.STORE) == 3
    assert decisions[-1] is PipelineDecision.SUPPRESSED


def test_repeats_aggregate_into_the_same_incident() -> None:
    pipeline, clock = make_pipeline(
        dedup_window=0.0, cooldown=0.0, aggregate_window=900.0, rate_limit_count=100
    )
    event = make_event()

    first = pipeline.submit(event)
    clock.advance(10.0)
    second = pipeline.submit(event)

    assert first.decision is PipelineDecision.STORE
    assert second.decision is PipelineDecision.AGGREGATE
    assert second.incident_id == first.incident_id
    assert second.count == 2


def test_incident_escalates_once_the_threshold_is_reached() -> None:
    pipeline, clock = make_pipeline(
        dedup_window=0.0, cooldown=0.0, aggregate_window=900.0, escalate_at=3
    )
    event = make_event()

    assert pipeline.submit(event).decision is PipelineDecision.STORE
    clock.advance(1.0)
    assert pipeline.submit(event).decision is PipelineDecision.AGGREGATE
    clock.advance(1.0)
    escalated = pipeline.submit(event)

    assert escalated.decision is PipelineDecision.STORE
    assert escalated.severity is Severity.CRITICAL
    assert escalated.count == 3


def test_severity_escalation_is_capped_at_critical() -> None:
    assert Severity.MEDIUM.escalated() is Severity.HIGH
    assert Severity.HIGH.escalated() is Severity.CRITICAL
    assert Severity.CRITICAL.escalated() is Severity.CRITICAL


def test_tracked_keys_are_bounded() -> None:
    pipeline, _ = make_pipeline(
        dedup_window=0.0,
        cooldown=0.0,
        aggregate_window=0.0,
        rate_limit_count=1,
        max_tracked_keys=10,
        global_limit_count=1000,
    )

    for i in range(200):
        pipeline.submit(make_event(src_ip=f"10.0.0.{i % 256}", dst_ip=f"10.1.{i // 256}.1"))

    assert pipeline.tracked_key_count <= 10


def test_ten_thousand_event_burst_yields_bounded_alerts() -> None:
    pipeline, _ = make_pipeline()

    stores = 0
    for _ in range(10_000):
        if pipeline.submit(make_event()).decision is PipelineDecision.STORE:
            stores += 1

    assert stores == 1
