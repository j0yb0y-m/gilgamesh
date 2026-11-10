"""The Settings → AI explanations card: save, probe, and clear the key.

The key is write-only: the form never renders it back, a blank field means
"unchanged", and the only status shown is whether an encrypted row exists and
whether the key file can still decrypt it. Saving validates the URL before it is
stored, so a bad host cannot become an outbound request later.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import RedirectResponse, Response

from gilgamesh.ai.providers import (
    AiConfigError,
    ProviderError,
    probe_provider,
    validate_base_url,
)
from gilgamesh.ai.secrets import AiKeyStore
from gilgamesh.ai.settings import AiSettings, AiSettingsError, AiSettingsStore, validate_settings
from gilgamesh.web.auth import Session
from gilgamesh.web.deps import read_form, require_session, verify_csrf
from gilgamesh.web.routes.settings import render_settings_page

router = APIRouter()

_TRUTHY = frozenset({"1", "true", "yes", "on"})


@router.post("/settings/ai", dependencies=[Depends(verify_csrf)])
async def ai_save(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Persist the AI settings, leaving the key alone when the field is blank."""
    current: AiSettings = request.app.state.ai_settings.get()
    form = await read_form(request)
    try:
        settings, api_key = _submitted(form, current)
    except AiSettingsError as exc:
        return render_settings_page(request, session, error=f"Not saved: {exc}")

    try:
        validate_base_url(settings.base_url, local_provider=settings.local_provider)
    except AiConfigError as exc:
        return render_settings_page(request, session, error=f"Not saved: {exc}", ai=settings)

    keys: AiKeyStore = request.app.state.ai_keys
    if api_key:
        try:
            keys.set_key(api_key)
        except OSError:
            return render_settings_page(
                request,
                session,
                error="Not saved: the key file could not be written.",
                ai=settings,
            )
        request.app.state.db.insert_audit_entry(f"AI API key set by {session.user.username}")

    store: AiSettingsStore = request.app.state.ai_settings
    updated = store.update(**settings.model_dump())
    request.app.state.db.insert_audit_entry(
        f"AI settings updated ({'enabled' if updated.enabled else 'disabled'}, "
        f"preset {updated.preset}) by {session.user.username}"
    )
    return RedirectResponse("/settings?saved=ai", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/settings/ai/test", dependencies=[Depends(verify_csrf)])
async def ai_test(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Probe the submitted provider without saving anything."""
    current: AiSettings = request.app.state.ai_settings.get()
    form = await read_form(request)
    try:
        settings, api_key = _submitted(form, current)
    except AiSettingsError as exc:
        return render_settings_page(request, session, error=f"Connection failed: {exc}")

    key = api_key or request.app.state.ai_keys.get_key()
    try:
        probe = await probe_provider(settings, key, transport=request.app.state.ai_transport)
    except (AiConfigError, ProviderError) as exc:
        return render_settings_page(
            request, session, error=f"Connection failed: {exc}", ai=settings
        )
    return render_settings_page(
        request,
        session,
        notice=f"Connection OK: {probe.model} in {probe.latency_ms} ms",
        ai=settings,
    )


@router.post("/settings/ai/key/clear", dependencies=[Depends(verify_csrf)])
async def ai_key_clear(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Delete the encrypted key row. The key file stays for the next key."""
    keys: AiKeyStore = request.app.state.ai_keys
    keys.clear_key()
    request.app.state.db.insert_audit_entry(f"AI API key cleared by {session.user.username}")
    return RedirectResponse("/settings?saved=ai_key_cleared", status_code=status.HTTP_303_SEE_OTHER)


def _submitted(form: dict[str, str], current: AiSettings) -> tuple[AiSettings, str]:
    """Validate the form against the stored settings and return the key field."""
    try:
        max_tokens = int(form.get("max_tokens", str(current.max_tokens)))
        timeout_s = float(form.get("timeout_s", str(current.timeout_s)))
    except ValueError as exc:
        raise AiSettingsError("max tokens and timeout must be numbers") from exc
    settings = validate_settings(
        current,
        enabled=_truthy(form, "enabled"),
        preset=form.get("preset", current.preset).strip(),
        kind=form.get("kind", current.kind).strip(),
        base_url=form.get("base_url", current.base_url).strip(),
        model=form.get("model", current.model).strip(),
        max_tokens=max_tokens,
        timeout_s=timeout_s,
        local_provider=_truthy(form, "local_provider"),
        redact_mac=_truthy(form, "redact_mac"),
        redact_hostname=_truthy(form, "redact_hostname"),
        redact_ips=_truthy(form, "redact_ips"),
    )
    return settings, form.get("api_key", "").strip()


def _truthy(form: dict[str, str], name: str) -> bool:
    return form.get(name, "") in _TRUTHY


__all__ = ["router"]
