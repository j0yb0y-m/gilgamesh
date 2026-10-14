"""The device inventory: trust and rename the devices seen on the network."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response

from gilgamesh.devices import DeviceStore
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
    return templates.TemplateResponse(
        request=request,
        name="devices.html",
        context={
            "session": session,
            "devices": devices,
            "total": len(store.list()),
            "show": show,
            "notice": notice,
            "error": error,
        },
    )
