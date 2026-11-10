"""The explanation service: choose AI or template, cache, and fail safely.

The service is the only code that decides whether an outbound AI request happens.
AI is opt-in; a disabled setting, a missing key, an open circuit, an oversized
context, or any provider failure all fall back to the deterministic template. A
successful answer is cached, a failure is recorded as an audit row, and three
consecutive failures pause AI for five minutes.

Concurrent clicks for the same event share one in-flight task, so a double click
cannot spend the owner's budget twice.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

import httpx

from gilgamesh.ai.cache import ExplanationCache, ExplanationRow
from gilgamesh.ai.context import (
    ContextTooLarge,
    ExplanationContext,
    RedactionSettings,
    build_explanation_context,
)
from gilgamesh.ai.prompt import PROMPT_VERSION, SYSTEM_PROMPT, build_user_prompt
from gilgamesh.ai.providers import (
    AiConfigError,
    ExplanationProvider,
    ExplanationRequest,
    ProviderError,
    build_provider,
)
from gilgamesh.ai.secrets import AiKeyStore
from gilgamesh.ai.settings import AiSettings, AiSettingsStore, preset
from gilgamesh.ai.templates import TemplateProvider, template_explanation
from gilgamesh.behaviour.store import BehaviourStore, DeviceProfile
from gilgamesh.db import Database
from gilgamesh.models import Event
from gilgamesh.preferences import PreferencesStore

logger = logging.getLogger(__name__)

#: The provider may return more than the prompt asked for; the UI and cache keep
#: only this many characters.
MAX_OUTPUT_CHARS = 4_000

#: Three consecutive failures pause AI for five minutes.
CIRCUIT_FAILURES = 3
CIRCUIT_SECONDS = 300.0

DISCLAIMER = "AI-generated explanation. It may be wrong — check the evidence before acting."

_TEMPLATE_OFF = "AI explanations are off."
_TEMPLATE_NO_KEY = "No API key configured."
_TEMPLATE_CIRCUIT = "AI temporarily unavailable — showing the standard explanation."
_TEMPLATE_TOO_LARGE = "The evidence was too large to send."
_TEMPLATE_FAILED = "AI request failed — showing the standard explanation."


@dataclass(frozen=True, slots=True)
class ExplanationOutcome:
    """What the UI renders and what the service decided."""

    text: str
    source: Literal["ai", "template"]
    provider: str
    model: str
    cached: bool
    reason: str = ""
    disclaimer: str = DISCLAIMER


class ExplanationService:
    """Turn one event into an AI or template explanation, with caching."""

    def __init__(
        self,
        database: Database,
        ai_settings: AiSettingsStore,
        ai_keys: AiKeyStore,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        provider_factory: Callable[..., ExplanationProvider] = build_provider,
        template_provider: ExplanationProvider | None = None,
    ) -> None:
        self._db = database
        self._settings = ai_settings
        self._keys = ai_keys
        self._transport = transport
        self._clock = clock
        self._provider_factory = provider_factory
        self._template_provider = template_provider or TemplateProvider()
        self._cache = ExplanationCache(database)
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0
        self._inflight: dict[str, asyncio.Task[ExplanationOutcome]] = {}

    async def explain(self, event: Event, *, regenerate: bool = False) -> ExplanationOutcome:
        """Explain ``event``, sharing an in-flight request for the same event."""
        existing = self._inflight.get(event.id)
        if existing is not None:
            return await existing
        task = asyncio.create_task(self._explain(event, regenerate=regenerate))
        self._inflight[event.id] = task
        try:
            return await task
        finally:
            self._inflight.pop(event.id, None)

    async def _explain(self, event: Event, *, regenerate: bool) -> ExplanationOutcome:
        settings = self._settings.get()
        context = self._build_context(event, settings)

        if not settings.enabled:
            return await self._template(context, _TEMPLATE_OFF, settings)

        key = self._keys.get_key()
        if preset(settings.preset).requires_key and not key:
            return await self._template(context, _TEMPLATE_NO_KEY, settings)

        if self._clock() < self._circuit_open_until:
            return await self._template(context, _TEMPLATE_CIRCUIT, settings)

        if not regenerate:
            cached = self._cache.get(event.id, settings.preset, settings.model, PROMPT_VERSION)
            if cached is not None:
                return ExplanationOutcome(
                    text=cached.text,
                    source="ai",
                    provider=cached.provider,
                    model=cached.model,
                    cached=True,
                )

        try:
            user_prompt = build_user_prompt(context)
        except ContextTooLarge:
            return await self._template(context, _TEMPLATE_TOO_LARGE, settings)

        try:
            provider = self._provider_factory(settings, key, transport=self._transport)
            result = await provider.explain(
                ExplanationRequest(
                    system_prompt=SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    context=cast("dict[str, object]", context.model_dump(mode="json")),
                    max_tokens=settings.max_tokens,
                    timeout_s=settings.timeout_s,
                )
            )
            text = result.text.strip()[:MAX_OUTPUT_CHARS]
            if not text:
                raise ProviderError("invalid response")
        except Exception as exc:
            reason = _failure_reason(exc)
            self._record_failure(settings, event)
            logger.warning("AI explanation failed: %s", reason)
            return await self._template(context, reason, settings)

        self._consecutive_failures = 0
        self._circuit_open_until = 0.0
        self._cache.put(
            ExplanationRow(
                id=None,
                event_id=event.id,
                provider=settings.preset,
                model=settings.model,
                prompt_version=PROMPT_VERSION,
                status="ok",
                text=text,
                latency_ms=result.latency_ms,
                prompt_tokens=result.prompt_tokens,
                completion_tokens=result.completion_tokens,
                created_ts=datetime.now(UTC),
            )
        )
        return ExplanationOutcome(
            text=text,
            source="ai",
            provider=result.provider,
            model=result.model,
            cached=False,
        )

    async def _template(
        self,
        context: ExplanationContext,
        reason: str,
        settings: AiSettings,
    ) -> ExplanationOutcome:
        """Render the deterministic explanation, with the injected provider if any."""
        request = ExplanationRequest(
            system_prompt=SYSTEM_PROMPT,
            user_prompt="",
            context=cast("dict[str, object]", context.model_dump(mode="json")),
            max_tokens=settings.max_tokens,
            timeout_s=settings.timeout_s,
        )
        try:
            result = await self._template_provider.explain(request)
            text = result.text
            provider = result.provider
            model = result.model
        except Exception:
            logger.warning("template explanation failed; using the built-in text")
            text = template_explanation(context)
            provider = "template"
            model = ""
        return ExplanationOutcome(
            text=text,
            source="template",
            provider=provider,
            model=model,
            cached=False,
            reason=reason,
        )

    def _record_failure(self, settings: AiSettings, event: Event) -> None:
        """Count one failure, maybe open the circuit, and keep an audit row."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= CIRCUIT_FAILURES:
            self._circuit_open_until = self._clock() + CIRCUIT_SECONDS
        self._cache.put(
            ExplanationRow(
                id=None,
                event_id=event.id,
                provider=settings.preset,
                model=settings.model,
                prompt_version=PROMPT_VERSION,
                status="error",
                text="",
                latency_ms=None,
                prompt_tokens=None,
                completion_tokens=None,
                created_ts=datetime.now(UTC),
            )
        )

    def _build_context(self, event: Event, settings: AiSettings) -> ExplanationContext:
        """Load the incident, related events, and device profile for ``event``."""
        redaction = RedactionSettings(
            redact_mac=settings.redact_mac,
            redact_hostname=settings.redact_hostname,
            redact_ips=settings.redact_ips,
        )
        incident = (
            self._db.get_incident(event.incident_id) if event.incident_id is not None else None
        )
        return build_explanation_context(
            event,
            incident_row=incident,
            related_events=self._related_events(event),
            behaviour_profile=self._device_profile(event),
            redaction=redaction,
        )

    def _related_events(self, event: Event) -> list[Event]:
        """Other events from the same incident, bounded before the context filter."""
        if event.incident_id is None:
            return []
        try:
            candidates = (
                self._db.events_for_device(event.src_mac, limit=50)
                if event.src_mac
                else self._db.list_events(limit=50)
            )
        except ValueError:
            candidates = self._db.list_events(limit=50)
        return [item for item in candidates if item.incident_id == event.incident_id]

    def _device_profile(self, event: Event) -> DeviceProfile | None:
        """The device's last-24-hours profile, or ``None`` when it has no MAC."""
        if not event.src_mac:
            return None
        try:
            calibration_days = PreferencesStore(self._db).get().behaviour_calibration_days
            return BehaviourStore(self._db).device_profile(
                event.src_mac,
                now=datetime.now(UTC),
                calibration_days=calibration_days,
            )
        except ValueError:
            return None


def _failure_reason(exc: Exception) -> str:
    """A safe, short reason that never contains the key or the prompt."""
    if isinstance(exc, (ProviderError, AiConfigError)):
        message = str(exc).strip()
        if message:
            return f"AI request failed: {message}"
    return _TEMPLATE_FAILED


__all__ = [
    "CIRCUIT_FAILURES",
    "CIRCUIT_SECONDS",
    "DISCLAIMER",
    "MAX_OUTPUT_CHARS",
    "ExplanationOutcome",
    "ExplanationService",
]
