"""The template explanation is the offline, always-available fallback.

Every event type must get a genuinely useful three-section explanation, the text
must be deterministic, and it must never repeat an identifier the redaction
settings hid. These tests also pin that ``TemplateProvider`` can consume the
serialized context the service will hand it.
"""

from __future__ import annotations

from typing import cast

from gilgamesh.ai.context import (
    DeviceSummary,
    ExplanationContext,
    RedactionSettings,
)
from gilgamesh.ai.providers import ExplanationRequest
from gilgamesh.ai.templates import TemplateProvider, template_explanation
from gilgamesh.models import EventType, Severity

MAC = "aa:bb:cc:dd:ee:01"
IP = "10.0.0.20"


def context_for(
    event_type: EventType,
    *,
    facts: dict[str, object] | None = None,
    redact: bool = True,
    device: DeviceSummary | None = None,
) -> ExplanationContext:
    return ExplanationContext(
        event_type=event_type,
        severity=Severity.MEDIUM,
        detector="test",
        facts=facts or {},
        incident=None,
        related=[],
        device=device,
        redaction=RedactionSettings(redact, redact, redact),
    )


def test_every_event_type_gets_three_useful_sections() -> None:
    for event_type in EventType:
        text = template_explanation(context_for(event_type))
        assert "What happened" in text
        assert "Why it matters" in text
        assert "What to check" in text
        assert 20 <= len(text.split()) <= 220


def test_behaviour_templates_include_the_evidence_numbers() -> None:
    volume = template_explanation(
        context_for(
            EventType.BEHAVIOUR_ANOMALY,
            facts={
                "signal": "volume_spike",
                "observed_bytes": 1_800_000_000,
                "baseline_mean_bytes": 4_200_000,
                "ratio": 428.6,
                "direction": "out",
                "window_end": "2026-11-10T11:45:00+00:00",
            },
        )
    )
    assert "1,800,000,000" in volume
    assert "428" in volume

    beacon = template_explanation(
        context_for(
            EventType.BEHAVIOUR_ANOMALY,
            facts={
                "signal": "beaconing",
                "connections": 60,
                "mean_interval_s": 60.0,
                "cov": 0.02,
            },
        )
    )
    assert "60" in beacon

    destinations = template_explanation(
        context_for(
            EventType.BEHAVIOUR_ANOMALY,
            facts={"signal": "new_destinations", "new_destinations": 42, "threshold": 12.5},
        )
    )
    assert "42" in destinations


def test_template_never_contains_a_redacted_mac_ip_or_hostname() -> None:
    text = template_explanation(
        context_for(
            EventType.NEW_DEVICE,
            facts={
                "reason": "new_device",
                "mac": MAC,
                "ips": [IP],
                "hostname": "camera.local",
            },
            device=DeviceSummary(label="camera.local"),
        )
    )

    assert MAC not in text
    assert IP not in text
    assert "camera.local" not in text


def test_template_is_deterministic() -> None:
    context = context_for(
        EventType.ARP_SPOOF,
        facts={"reason": "gateway_mac_changed", "count": 4, "window_seconds": 60},
    )

    assert template_explanation(context) == template_explanation(context)


def test_unknown_behaviour_signal_uses_a_generic_template() -> None:
    text = template_explanation(
        context_for(
            EventType.BEHAVIOUR_ANOMALY,
            facts={"signal": "mystery_signal", "z_score": 9.9},
        )
    )

    assert "mystery signal" in text
    assert "What happened" in text


def test_test_event_says_there_is_nothing_to_explain() -> None:
    text = template_explanation(context_for(EventType.TEST))

    assert "Nothing to explain" in text
    assert "What happened" in text
    assert "Why it matters" in text
    assert "What to check" in text


def test_template_never_uses_markdown_tables_or_code_fences() -> None:
    for event_type in EventType:
        text = template_explanation(context_for(event_type))
        assert "```" not in text
        assert "|---" not in text


async def test_template_provider_consumes_the_serialized_context() -> None:
    context = context_for(
        EventType.ARP_SPOOF,
        facts={"reason": "gateway_mac_changed", "count": 4},
    )
    request = ExplanationRequest(
        system_prompt="system",
        user_prompt="user",
        context=cast("dict[str, object]", context.model_dump(mode="json")),
        max_tokens=400,
        timeout_s=5.0,
    )

    result = await TemplateProvider().explain(request)

    assert result.provider == "template"
    assert result.model == ""
    assert result.latency_ms == 0
    assert result.text == template_explanation(context)
    assert "What happened" in result.text
