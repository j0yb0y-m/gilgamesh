"""Build the only event data that may be sent to an AI provider.

The context is assembled from a per-``EventType`` whitelist, never from
``Event.details`` wholesale. That distinction is the privacy boundary: existing
detectors put MACs, IPs, qnames, and server identifiers in ``details``, and the
free-text ``summary`` often repeats them. Only the keys in :data:`SAFE_FACTS`
travel, every string is length-bounded and stripped of control characters, and
identifiers are replaced by default.

The rendered payload is capped at :data:`MAX_CONTEXT_BYTES`; the caller falls
back to the deterministic template rather than sending an oversized request.
"""

from __future__ import annotations

import math
import re
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from pydantic import BaseModel, ConfigDict, Field

from gilgamesh.behaviour.baseline import metric_is_log
from gilgamesh.behaviour.store import ActivityBucket, DeviceProfile
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.util.net import normalize_mac

#: Hard cap on the rendered JSON. A normal context is a few kilobytes; ten related
#: events with long signatures can grow, and a provider prompt is not the place to
#: discover that.
MAX_CONTEXT_BYTES = 16 * 1024

#: Every free-text fact is truncated to this many characters.
MAX_STRING_CHARS = 500

#: Lists such as ``all_reasons`` or ``ports`` are bounded independently.
MAX_LIST_ITEMS = 20

#: The spec allows at most ten related events from the same incident.
MAX_RELATED_EVENTS = 10

#: The facts each detector may contribute. Anything not listed here is excluded,
#: including ``summary``, ``qname``, ``hostname``, ``mac``, ``ip``, and ``ips``.
SAFE_FACTS: dict[EventType, tuple[str, ...]] = {
    EventType.ARP_SPOOF: ("reason", "count", "window_seconds", "suspicious_ttl"),
    EventType.DNS_SPOOF: (
        "reason",
        "all_reasons",
        "dns_id",
        "min_ttl",
        "suspicious_ttl",
        "authoritative",
    ),
    EventType.DHCP_ROGUE: (
        "reason",
        "message_type",
        "discover_count",
        "distinct_clients",
        "window_seconds",
        "changed",
    ),
    EventType.PORT_SCAN: (
        "reason",
        "distinct_ports",
        "distinct_hosts",
        "threshold",
        "window_seconds",
        "ports",
    ),
    EventType.SYN_FLOOD: ("reason", "syn_count", "threshold", "target"),
    EventType.NEW_DEVICE: ("reason", "randomised", "trusted"),
    EventType.SURICATA_ALERT: (
        "signature",
        "signature_id",
        "rev",
        "gid",
        "category",
        "action",
        "suricata_severity",
        "proto",
        "app_proto",
    ),
    EventType.BEHAVIOUR_ANOMALY: (
        "signal",
        "window_start",
        "window_end",
        "observed_bytes",
        "baseline_mean_bytes",
        "baseline_std_log",
        "z_score",
        "ratio",
        "samples",
        "consecutive_buckets",
        "direction",
        "new_destinations",
        "threshold",
        "connections",
        "cov",
        "mean_interval_s",
        "total_bytes",
    ),
    EventType.TEST: (),
}

_MAC_RE = re.compile(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_BUCKET_METRICS = {
    "bytes_out_log": "bytes_out",
    "bytes_in_log": "bytes_in",
    "unique_dst": "unique_dst",
    "dns_queries": "dns_queries",
}


@dataclass(frozen=True, slots=True)
class RedactionSettings:
    """Which identifiers may leave the box. All three default to hidden."""

    redact_mac: bool = True
    redact_hostname: bool = True
    redact_ips: bool = True


class IncidentSummary(BaseModel):
    """How often and for how long the incident behind this event has repeated."""

    model_config = ConfigDict(frozen=True)

    count: int
    first_ts: datetime
    last_ts: datetime


class RelatedEvent(BaseModel):
    """A bounded, whitelisted glimpse of another event in the same incident."""

    model_config = ConfigDict(frozen=True)

    type: EventType
    severity: Severity
    detector: str
    ts: datetime
    facts: dict[str, object] = Field(default_factory=dict[str, object])


class DeviceSummary(BaseModel):
    """The device's calibration state and its normal-versus-recent numbers.

    ``normal`` and ``now`` are in natural units (bytes, counts) per 15-minute
    bucket. Log-metric baselines are converted back with ``expm1`` so the model
    never has to understand the storage transform.
    """

    model_config = ConfigDict(frozen=True)

    label: str | None = None
    vendor: str | None = None
    trusted: bool = False
    randomised: bool = False
    calibration_state: str = "none"
    normal: dict[str, float] = Field(default_factory=dict[str, float])
    now: dict[str, float] = Field(default_factory=dict[str, float])


class ExplanationContext(BaseModel):
    """Everything an explanation may see about one event."""

    model_config = ConfigDict(frozen=True)

    event_type: EventType
    severity: Severity
    detector: str
    facts: dict[str, object] = Field(default_factory=dict[str, object])
    incident: IncidentSummary | None = None
    related: list[RelatedEvent] = Field(default_factory=list[RelatedEvent])
    device: DeviceSummary | None = None
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)


class ContextTooLarge(RuntimeError):
    """The rendered context exceeded :data:`MAX_CONTEXT_BYTES`."""


def build_explanation_context(
    event: Event,
    *,
    incident_row: Mapping[str, object] | sqlite3.Row | None,
    related_events: Sequence[Event],
    behaviour_profile: DeviceProfile | None,
    redaction: RedactionSettings,
) -> ExplanationContext:
    """Assemble the redacted, whitelisted context for ``event``.

    ``related_events`` is filtered to the same source device and capped at ten.
    A related event contributes only its own safe facts, never its summary or raw
    details, so another device's identifiers cannot ride along.
    """
    return ExplanationContext(
        event_type=event.type,
        severity=event.severity,
        detector=event.detector,
        facts=_safe_facts(event, redaction),
        incident=_incident_summary(incident_row),
        related=_related_events(event, related_events, redaction),
        device=_device_summary(behaviour_profile, redaction),
        redaction=redaction,
    )


def render_context(context: ExplanationContext) -> str:
    """Serialize the context as bounded JSON, or raise :class:`ContextTooLarge`."""
    payload = context.model_dump_json(indent=2, exclude_none=True)
    if len(payload.encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ContextTooLarge("explanation context is too large to send")
    return payload


def redact_text(text: str, settings: RedactionSettings) -> str:
    """Replace MAC and IP literals according to ``settings``.

    Hostnames cannot be recognised reliably in free text; callers replace known
    hostname fields (the device label) wholesale when ``redact_hostname`` is on.
    """
    result = text
    if settings.redact_mac:
        result = _MAC_RE.sub("[redacted mac]", result)
    if settings.redact_ips:
        result = _IPV4_RE.sub("[redacted ip]", result)
        result = _IPV6_RE.sub(_redact_ipv6, result)
    return result


def _redact_ipv6(match: re.Match[str]) -> str:
    """Replace an IPv6 literal, but leave a MAC alone when MAC redaction is off."""
    value = match.group(0)
    if _MAC_RE.fullmatch(value):
        return value
    return "[redacted ip]"


def _safe_facts(event: Event, settings: RedactionSettings) -> dict[str, object]:
    """Keep only the whitelisted, JSON-safe, sanitized details for this type."""
    facts: dict[str, object] = {}
    for key in SAFE_FACTS.get(event.type, ()):
        if key not in event.details:
            continue
        value = _sanitize(event.details[key], settings)
        if value is not None:
            facts[key] = value
    return facts


def _sanitize(value: object, settings: RedactionSettings) -> object | None:
    """Return a JSON-safe scalar or bounded list, or ``None`` to drop it."""
    scalar = _sanitize_scalar(value, settings)
    if scalar is not None:
        return scalar
    if isinstance(value, list | tuple):
        source = cast("Sequence[object]", value)
        items = [
            cleaned
            for item in source[:MAX_LIST_ITEMS]
            if (cleaned := _sanitize_scalar(item, settings)) is not None
        ]
        return items or None
    return None


def _sanitize_scalar(value: object, settings: RedactionSettings) -> object | None:
    """Sanitize one JSON scalar; reject bytes, mappings, and non-finite floats."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        text = _CONTROL_RE.sub("", value).strip()
        if not text:
            return None
        return redact_text(text, settings)[:MAX_STRING_CHARS]
    return None


def _related_events(
    event: Event, candidates: Sequence[Event], settings: RedactionSettings
) -> list[RelatedEvent]:
    """Keep up to ten other events from the same source device."""
    anchor = _device_key(event.src_mac)
    related: list[RelatedEvent] = []
    for candidate in candidates:
        if candidate.id == event.id:
            continue
        if _device_key(candidate.src_mac) != anchor:
            continue
        related.append(
            RelatedEvent(
                type=candidate.type,
                severity=candidate.severity,
                detector=candidate.detector,
                ts=candidate.ts,
                facts=_safe_facts(candidate, settings),
            )
        )
        if len(related) == MAX_RELATED_EVENTS:
            break
    return related


def _device_key(mac: str | None) -> str | None:
    """Normalize a MAC for comparison, tolerating detector-supplied oddities."""
    if mac is None:
        return None
    try:
        return normalize_mac(mac)
    except ValueError:
        return mac.strip().lower()


def _incident_summary(
    row: Mapping[str, object] | sqlite3.Row | None,
) -> IncidentSummary | None:
    """Build the incident summary from a mapping or a ``sqlite3.Row``."""
    if row is None:
        return None
    count = _row_value(row, "count")
    first = _as_datetime(_row_value(row, "first_ts"))
    last = _as_datetime(_row_value(row, "last_ts"))
    if not isinstance(count, int) or isinstance(count, bool):
        return None
    if first is None or last is None:
        return None
    return IncidentSummary(count=count, first_ts=first, last_ts=last)


def _row_value(row: Mapping[str, object] | sqlite3.Row, key: str) -> object:
    """Read one column from either a mapping or a sqlite row."""
    if isinstance(row, sqlite3.Row):
        try:
            return cast(object, row[key])
        except IndexError:
            return None
    return row.get(key)


def _as_datetime(value: object) -> datetime | None:
    """Parse an ISO timestamp, attaching UTC when the source omitted a zone."""
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        return None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment


def _device_summary(
    profile: DeviceProfile | None, settings: RedactionSettings
) -> DeviceSummary | None:
    """Summarize calibration, baseline means, and the last 24 hours of buckets."""
    if profile is None:
        return None
    normal: dict[str, float] = {}
    for row in profile.baselines:
        if row.samples > 0:
            normal[row.metric] = round(_natural_units(row.metric, row.mean), 2)
    return DeviceSummary(
        label=_device_label(profile.summary.mac, settings),
        calibration_state=profile.summary.state,
        normal=normal,
        now=_recent_means(profile.buckets, set(normal)),
    )


def _device_label(raw: str, settings: RedactionSettings) -> str | None:
    """Treat the device label as a hostname, which is how the spec defines it."""
    if not raw:
        return None
    if settings.redact_hostname:
        return "[redacted hostname]"
    return redact_text(raw, settings)


def _natural_units(metric: str, mean: float) -> float:
    """Undo the ``log1p`` transform for log metrics."""
    return math.expm1(mean) if metric_is_log(metric) else mean


def _recent_means(buckets: Sequence[ActivityBucket], metrics: set[str]) -> dict[str, float]:
    """Average each metric over the profile's buckets, in natural units."""
    means: dict[str, float] = {}
    for metric in sorted(metrics):
        attribute = _BUCKET_METRICS.get(metric)
        if attribute is None or not buckets:
            continue
        total = sum(cast(int, getattr(bucket, attribute)) for bucket in buckets)
        means[metric] = round(total / len(buckets), 2)
    return means


__all__ = [
    "MAX_CONTEXT_BYTES",
    "SAFE_FACTS",
    "ContextTooLarge",
    "DeviceSummary",
    "ExplanationContext",
    "IncidentSummary",
    "RedactionSettings",
    "RelatedEvent",
    "build_explanation_context",
    "redact_text",
    "render_context",
]
