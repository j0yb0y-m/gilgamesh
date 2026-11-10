"""The explanation context is the only data that may leave the box.

These tests pin the promise made on the Settings page: the free-text summary and
raw ``details`` never travel, only per-type safe facts do, identifiers are
redacted by default, and the rendered payload is bounded. A failure here is a
privacy failure, not a cosmetic one.
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

import pytest

from gilgamesh.ai.context import (
    MAX_CONTEXT_BYTES,
    SAFE_FACTS,
    ContextTooLarge,
    ExplanationContext,
    IncidentSummary,
    RedactionSettings,
    build_explanation_context,
    redact_text,
    render_context,
)
from gilgamesh.behaviour.store import (
    ActivityBucket,
    BaselineRow,
    DeviceBehaviourSummary,
    DeviceProfile,
)
from gilgamesh.models import Event, EventType, Severity

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
MAC = "aa:bb:cc:dd:ee:01"
OTHER_MAC = "aa:bb:cc:dd:ee:02"


def make_event(
    *,
    event_type: EventType = EventType.ARP_SPOOF,
    severity: Severity = Severity.HIGH,
    detector: str = "arp",
    summary: str = "a summary that must never leave the box",
    details: dict[str, object] | None = None,
    src_mac: str | None = MAC,
    src_ip: str | None = "10.0.0.20",
    event_id: str | None = None,
) -> Event:
    values: dict[str, object] = {
        "ts": NOW,
        "type": event_type,
        "severity": severity,
        "detector": detector,
        "summary": summary,
        "src_mac": src_mac,
        "src_ip": src_ip,
        "details": details or {},
    }
    if event_id is not None:
        values["id"] = event_id
    return Event(**values)  # type: ignore[arg-type]


def make_profile(
    *,
    label: str = MAC,
    state: Literal["disabled", "none", "learning", "calibrated"] = "calibrated",
    baselines: tuple[BaselineRow, ...] = (),
    buckets: tuple[ActivityBucket, ...] = (),
) -> DeviceProfile:
    return DeviceProfile(
        summary=DeviceBehaviourSummary(
            mac=label,
            state=state,
            days_learning=7,
            calibration_days=7,
            samples=max((row.samples for row in baselines), default=0),
        ),
        buckets=buckets,
        baselines=baselines,
        recent_events=(),
    )


def build(
    event: Event,
    *,
    incident_row: object = None,
    related_events: list[Event] | None = None,
    profile: DeviceProfile | None = None,
    redaction: RedactionSettings | None = None,
) -> ExplanationContext:
    return build_explanation_context(
        event,
        incident_row=incident_row,  # type: ignore[arg-type]
        related_events=related_events or [],
        behaviour_profile=profile,
        redaction=redaction or RedactionSettings(),
    )


def test_summary_and_unsafe_details_are_never_sent() -> None:
    event = make_event(
        summary=f"Gateway {MAC} at 10.0.0.1 changed",
        details={
            "previous_mac": MAC,
            "ip": "10.0.0.1",
            "payload": b"secret",
            "reason": "gateway_mac_changed",
            "count": 3,
            "window_seconds": 60,
            "suspicious_ttl": True,
        },
    )

    context = build(event)
    payload = render_context(context)

    assert "Gateway aa:bb" not in payload
    assert "secret" not in payload
    assert "previous_mac" not in payload
    assert context.facts == {
        "reason": "gateway_mac_changed",
        "count": 3,
        "window_seconds": 60,
        "suspicious_ttl": True,
    }


def test_redaction_replaces_mac_ip_and_hostname_and_can_be_disabled() -> None:
    event = make_event(details={"reason": f"gateway {MAC} at 10.0.0.20"})
    profile = make_profile(label="camera.local")

    on = build(event, profile=profile)
    payload = render_context(on)

    assert MAC not in payload
    assert "10.0.0.20" not in payload
    assert "camera.local" not in payload
    assert "[redacted mac]" in payload
    assert "[redacted ip]" in payload
    assert "[redacted hostname]" in payload

    off = build(
        event,
        profile=profile,
        redaction=RedactionSettings(False, False, False),
    )
    payload = render_context(off)

    assert MAC in payload
    assert "10.0.0.20" in payload
    assert "camera.local" in payload


def test_device_label_is_controlled_by_hostname_redaction() -> None:
    profile = make_profile(label="camera.local")

    hidden = build(
        make_event(),
        profile=profile,
        redaction=RedactionSettings(redact_mac=True, redact_hostname=True, redact_ips=True),
    )
    shown = build(
        make_event(),
        profile=profile,
        redaction=RedactionSettings(redact_mac=True, redact_hostname=False, redact_ips=True),
    )

    assert hidden.device is not None and hidden.device.label == "[redacted hostname]"
    assert shown.device is not None and shown.device.label == "camera.local"


def test_each_event_type_keeps_only_its_whitelisted_facts() -> None:
    all_details: dict[str, object] = {key: "value" for keys in SAFE_FACTS.values() for key in keys}
    all_details.update(
        {
            "qname": "bank.example",
            "hostname": "camera.local",
            "mac": MAC,
            "ip": "10.0.0.20",
            "ips": ["10.0.0.20"],
            "payload": b"bytes",
            "summary": "free text",
        }
    )

    for event_type in EventType:
        context = build(make_event(event_type=event_type, details=all_details))
        assert set(context.facts) == set(SAFE_FACTS[event_type])


def test_dns_spoof_keeps_ttl_facts_but_never_qname_or_answers() -> None:
    context = build(
        make_event(
            event_type=EventType.DNS_SPOOF,
            details={
                "reason": "suspicious_ttl",
                "qname": "bank.example",
                "answers": ["10.0.0.20"],
                "min_ttl": 3,
                "suspicious_ttl": True,
                "authoritative": False,
            },
        )
    )

    assert context.facts == {
        "reason": "suspicious_ttl",
        "min_ttl": 3,
        "suspicious_ttl": True,
        "authoritative": False,
    }


def test_new_device_keeps_flags_but_never_mac_ips_or_hostname() -> None:
    context = build(
        make_event(
            event_type=EventType.NEW_DEVICE,
            severity=Severity.LOW,
            detector="inventory",
            details={
                "reason": "new_device",
                "randomised": True,
                "trusted": False,
                "mac": MAC,
                "ips": ["10.0.0.20"],
                "hostname": "camera.local",
            },
        )
    )

    assert context.facts == {
        "reason": "new_device",
        "randomised": True,
        "trusted": False,
    }


def test_strings_are_capped_and_control_characters_are_stripped() -> None:
    context = build(make_event(details={"reason": "a" * 700 + "\x00\x1f\n\t", "count": 1}))

    reason = context.facts["reason"]
    assert isinstance(reason, str)
    assert len(reason) == 500
    assert "\x00" not in reason
    assert "\x1f" not in reason
    assert "\n" not in reason


def test_lists_are_capped_at_twenty_and_each_item_is_sanitized() -> None:
    reasons = [f"reason {index}" for index in range(30)]
    context = build(
        make_event(
            event_type=EventType.DNS_SPOOF,
            details={"reason": "multi", "all_reasons": reasons},
        )
    )

    kept = context.facts["all_reasons"]
    assert isinstance(kept, list)
    items = cast("list[object]", kept)
    assert len(items) == 20
    assert items[0] == "reason 0"
    assert items[-1] == "reason 19"


def test_non_json_detail_values_are_dropped() -> None:
    context = build(
        make_event(
            details={
                "reason": {"nested": "not allowed"},
                "count": b"bytes",
                "window_seconds": float("nan"),
            }
        )
    )

    assert context.facts == {}


def test_related_events_are_ten_and_only_from_the_same_device() -> None:
    main = make_event(event_id="main")
    same_device = [
        make_event(
            event_id=f"same-{index}",
            details={"reason": "ip_mac_conflict", "count": index},
        )
        for index in range(12)
    ]
    other_device = make_event(
        event_id="other",
        src_mac=OTHER_MAC,
        details={"reason": "other device secret"},
    )

    context = build(
        main,
        related_events=[*same_device, other_device, main],
    )

    assert len(context.related) == 10
    assert all(item.facts["reason"] == "ip_mac_conflict" for item in context.related)
    payload = render_context(context)
    assert "other device secret" not in payload
    assert '"id"' not in payload


def test_incident_summary_is_included() -> None:
    context = build(
        make_event(),
        incident_row={
            "count": 47,
            "first_ts": "2026-11-10T09:00:00+00:00",
            "last_ts": "2026-11-10T11:59:00+00:00",
        },
    )

    assert context.incident == IncidentSummary(
        count=47,
        first_ts=datetime(2026, 11, 10, 9, 0, tzinfo=UTC),
        last_ts=datetime(2026, 11, 10, 11, 59, tzinfo=UTC),
    )
    assert '"count": 47' in render_context(context)


def test_device_summary_reports_natural_units_and_recent_averages() -> None:
    baselines = (
        BaselineRow(
            device_mac=MAC,
            metric="bytes_out_log",
            mean=math.log1p(2000),
            variance=0.1,
            samples=30,
            learning_started_ts=NOW - timedelta(days=8),
            updated_ts=NOW,
        ),
        BaselineRow(
            device_mac=MAC,
            metric="unique_dst",
            mean=4.0,
            variance=0.5,
            samples=30,
            learning_started_ts=NOW - timedelta(days=8),
            updated_ts=NOW,
        ),
    )
    buckets = (
        ActivityBucket(
            device_mac=MAC,
            bucket_ts=NOW - timedelta(minutes=30),
            bytes_out=1000,
            unique_dst=3,
        ),
        ActivityBucket(
            device_mac=MAC,
            bucket_ts=NOW - timedelta(minutes=15),
            bytes_out=3000,
            unique_dst=5,
        ),
    )

    context = build(make_event(), profile=make_profile(baselines=baselines, buckets=buckets))

    assert context.device is not None
    assert context.device.calibration_state == "calibrated"
    assert context.device.normal["bytes_out_log"] == pytest.approx(2000.0, rel=1e-6)
    assert context.device.normal["unique_dst"] == 4.0
    assert context.device.now["bytes_out_log"] == 2000.0
    assert context.device.now["unique_dst"] == 4.0


def test_test_event_has_no_facts() -> None:
    context = build(
        make_event(
            event_type=EventType.TEST,
            severity=Severity.INFO,
            detector="test",
            details={"reason": "walking_skeleton", "message": "hello"},
        )
    )

    assert context.facts == {}


def test_render_context_is_valid_bounded_json() -> None:
    payload = render_context(
        build(make_event(details={"reason": "gateway_mac_changed", "count": 3}))
    )

    assert len(payload.encode("utf-8")) <= MAX_CONTEXT_BYTES
    parsed = json.loads(payload)
    assert parsed["event_type"] == "arp_spoof"
    assert parsed["facts"]["reason"] == "gateway_mac_changed"
    assert "summary" not in parsed


def test_render_context_refuses_more_than_16_kib() -> None:
    context = ExplanationContext(
        event_type=EventType.ARP_SPOOF,
        severity=Severity.HIGH,
        detector="arp",
        facts={"blob": "x" * (MAX_CONTEXT_BYTES + 1)},
        incident=None,
        related=[],
        device=None,
        redaction=RedactionSettings(),
    )

    with pytest.raises(ContextTooLarge):
        render_context(context)


def test_redact_text_honours_each_flag() -> None:
    text = f"{MAC} 10.0.0.20 2001:db8::1"

    assert redact_text(text, RedactionSettings()) == ("[redacted mac] [redacted ip] [redacted ip]")
    assert (
        redact_text(
            text, RedactionSettings(redact_mac=False, redact_hostname=True, redact_ips=False)
        )
        == text
    )
    assert (
        redact_text(
            text, RedactionSettings(redact_mac=False, redact_hostname=True, redact_ips=True)
        )
        == f"{MAC} [redacted ip] [redacted ip]"
    )
