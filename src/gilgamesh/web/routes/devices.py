"""The device inventory: trust and rename the devices seen on the network."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response

from gilgamesh.behaviour.baseline import metric_is_log
from gilgamesh.behaviour.sparkline import build_sparkline
from gilgamesh.behaviour.store import (
    ActivityBucket,
    BaselineRow,
    BehaviourStore,
    DeviceBehaviourSummary,
)
from gilgamesh.devices import DeviceStore
from gilgamesh.preferences import Preferences
from gilgamesh.web.auth import Session
from gilgamesh.web.deps import read_form, require_session, templates, verify_csrf

router = APIRouter()


@router.get("/devices", response_class=HTMLResponse)
async def devices_page(
    request: Request,
    session: Annotated[Session, Depends(require_session)],
    show: str = "",
) -> Response:
    """Every device the sensor has seen, plus trust/rename controls."""
    return _devices_page(request, session, show=show)


@router.get("/devices/{mac}", response_class=HTMLResponse)
async def device_detail(
    request: Request,
    mac: str,
    session: Annotated[Session, Depends(require_session)],
    notice: str = "",
    error: str = "",
) -> Response:
    """One device's behaviour profile, sparkline, and recent events."""
    store: DeviceStore = request.app.state.devices
    try:
        device = store.get(mac)
    except ValueError:
        device = None
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such device")

    behaviour: BehaviourStore = request.app.state.behaviour
    preferences: Preferences = request.app.state.preferences.get()
    now = datetime.now(UTC)
    profile = behaviour.device_profile(
        device.mac,
        now=now,
        calibration_days=preferences.behaviour_calibration_days,
    )
    if not preferences.behaviour_enabled:
        profile = replace(profile, summary=replace(profile.summary, state="disabled"))
    new_destinations = behaviour.new_destinations_since(device.mac, since=now - timedelta(hours=24))
    return templates.TemplateResponse(
        request=request,
        name="device_detail.html",
        context={
            "session": session,
            "device": device,
            "profile": profile,
            "sparkline": build_sparkline(profile.buckets),
            "baselines": {row.metric: row for row in profile.baselines},
            "normal": {row.metric: _normal_value(row) for row in profile.baselines},
            "observed": _observed_metrics(profile.buckets, new_destinations),
            "notice": notice,
            "error": error,
        },
    )


@router.post("/devices/{mac}/trust", dependencies=[Depends(verify_csrf)])
async def device_trust(
    request: Request,
    mac: str,
    session: Annotated[Session, Depends(require_session)],
) -> Response:
    """Mark a device trusted or untrusted. Trust never hides its events."""
    store: DeviceStore = request.app.state.devices
    form = await read_form(request)
    trusted = form.get("trusted", "0") in {"1", "true", "yes", "on"}
    try:
        store.set_trusted(mac, trusted)
    except (KeyError, ValueError):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such device") from None
    verb = "trusted" if trusted else "untrusted"
    return _devices_page(request, session, notice=f"{mac} {verb}.")


@router.post("/devices/{mac}/rename", dependencies=[Depends(verify_csrf)])
async def device_rename(
    request: Request,
    mac: str,
    session: Annotated[Session, Depends(require_session)],
) -> Response:
    """Give a device a human-readable label."""
    store: DeviceStore = request.app.state.devices
    form = await read_form(request)
    try:
        store.rename(mac, form.get("hostname", ""))
    except (KeyError, ValueError):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such device") from None
    label = form.get("hostname", "").strip()
    notice = f"{mac} renamed to {label}." if label else f"{mac} label cleared."
    return _devices_page(request, session, notice=notice)


def _devices_page(
    request: Request, session: Session, *, notice: str = "", error: str = "", show: str = ""
) -> Response:
    """Render the device inventory."""
    store: DeviceStore = request.app.state.devices
    devices = store.list()
    if show == "untrusted":
        devices = [device for device in devices if not device.trusted]
    elif show == "trusted":
        devices = [device for device in devices if device.trusted]

    behaviour: BehaviourStore = request.app.state.behaviour
    preferences: Preferences = request.app.state.preferences.get()
    summaries: dict[str, DeviceBehaviourSummary] = behaviour.summaries(
        now=datetime.now(UTC),
        calibration_days=preferences.behaviour_calibration_days,
    )
    if not preferences.behaviour_enabled:
        summaries = {mac: replace(summary, state="disabled") for mac, summary in summaries.items()}
    return templates.TemplateResponse(
        request=request,
        name="devices.html",
        context={
            "session": session,
            "devices": devices,
            "summaries": summaries,
            "behaviour_enabled": preferences.behaviour_enabled,
            "total": len(store.list()),
            "show": show,
            "notice": notice,
            "error": error,
        },
    )


def _normal_value(row: BaselineRow) -> float:
    """A baseline mean back in the metric's natural units."""
    return math.expm1(row.mean) if metric_is_log(row.metric) else row.mean


def _observed_metrics(buckets: Sequence[ActivityBucket], new_destinations: int) -> dict[str, float]:
    """Average the last 24 hours into the units the baselines use.

    Bytes and counts are per 15-minute bucket, so the comparable 24-hour figure is
    the mean bucket. New destinations are a first-sighting event with no bucket
    column, so their 24-hour figure is the count itself.
    """
    if not buckets:
        return {
            "bytes_out_log": 0.0,
            "bytes_in_log": 0.0,
            "unique_dst": 0.0,
            "new_destinations": float(new_destinations),
            "dns_queries": 0.0,
        }
    count = len(buckets)
    return {
        "bytes_out_log": sum(bucket.bytes_out for bucket in buckets) / count,
        "bytes_in_log": sum(bucket.bytes_in for bucket in buckets) / count,
        "unique_dst": sum(bucket.unique_dst for bucket in buckets) / count,
        "new_destinations": float(new_destinations),
        "dns_queries": sum(bucket.dns_queries for bucket in buckets) / count,
    }
