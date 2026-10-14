"""Channel configuration and the "send test" action (Notifications page)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response

from gilgamesh.channels import ChannelConfigError, ChannelRecord, ChannelStore
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.notifiers.base import ChannelKind
from gilgamesh.web.auth import Session
from gilgamesh.web.deps import read_form, require_session, templates, verify_csrf

router = APIRouter()

KINDS: tuple[ChannelKind, ...] = (ChannelKind.DISCORD, ChannelKind.TELEGRAM, ChannelKind.EMAIL)


@router.get("/notifications", response_class=HTMLResponse)
async def notifications_page(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Configure the Discord, Telegram, and email channels."""
    return _notifications_page(request, session)


@router.post("/notifications/{kind}", dependencies=[Depends(verify_csrf)])
async def notifications_save(
    request: Request,
    kind: str,
    session: Annotated[Session, Depends(require_session)],
) -> Response:
    """Save a channel. Secrets are written server-side and never echoed back."""
    store: ChannelStore = request.app.state.channels
    try:
        channel_kind = ChannelKind(kind)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such channel") from None
    form = await read_form(request)
    try:
        store.save(
            channel_kind,
            fields=form,
            enabled=form.get("enabled", "") in {"1", "true", "yes", "on"},
            min_severity=form.get("min_severity", Severity.MEDIUM.value),
            quiet_start=form.get("quiet_start", ""),
            quiet_end=form.get("quiet_end", ""),
        )
    except ChannelConfigError as exc:
        return _notifications_page(
            request, session, error=f"Not saved: {exc}", focus=channel_kind.value
        )
    return _notifications_page(request, session, notice=f"{channel_kind.value} saved.")


@router.post("/notifications/{channel_id}/test", dependencies=[Depends(verify_csrf)])
async def notifications_test(
    request: Request,
    channel_id: int,
    session: Annotated[Session, Depends(require_session)],
) -> Response:
    """Send a real test message and report exactly what the transport said."""
    store: ChannelStore = request.app.state.channels
    record = store.get_by_id(channel_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such channel")
    if not ChannelStore.is_configured(record.kind, record.config):
        return _notifications_page(
            request,
            session,
            error=f"Save the {record.kind} settings before sending a test.",
            focus=record.kind.value,
        )

    result = await _send_test(request, store, record)
    if result.ok:
        notice = f"Test message sent to {record.kind}."
        if result.error:
            notice = f"{notice} ({result.error})"
        return _notifications_page(request, session, notice=notice, focus=record.kind.value)
    return _notifications_page(
        request,
        session,
        error=f"Test failed for {record.kind}: {result.error or 'unknown error'}",
        focus=record.kind.value,
    )


async def _send_test(request: Request, store: ChannelStore, record: ChannelRecord):
    """Deliver one test event, bypassing quiet hours and severity policy.

    A "send test" that is silently swallowed by quiet hours would be worse than
    useless, so the stored quiet window is cleared for this one message.
    """
    transports = request.app.state.channel_transports
    transport = transports.get(record.kind)
    without_quiet = record.model_copy(update={"quiet_start": None, "quiet_end": None})
    channel = store.build_channel(without_quiet, transport=transport)
    event = Event(
        type=EventType.TEST,
        severity=Severity.HIGH,
        detector="notifier",
        summary="Gilgamesh test message — this channel is working.",
    )
    return await channel.deliver(event)


def _notifications_page(
    request: Request, session: Session, *, notice: str = "", error: str = "", focus: str = ""
) -> Response:
    """Render the notifications page with one card per channel kind."""
    store: ChannelStore = request.app.state.channels
    cards: list[dict[str, object]] = []
    for kind in KINDS:
        record = store.get(kind)
        secrets = (
            {name: store.is_secret_set(record, name) for name in store.secret_fields(kind)}
            if record is not None
            else {}
        )
        cards.append(
            {
                "kind": kind.value,
                "record": record,
                "configured": record is not None
                and ChannelStore.is_configured(kind, record.config),
                "secrets": secrets,
            }
        )
    return templates.TemplateResponse(
        request=request,
        name="notifications.html",
        context={
            "session": session,
            "cards": cards,
            "severities": [level.value for level in Severity],
            "notice": notice,
            "error": error,
            "focus": focus,
        },
    )
