"""Detection rules and the source allowlist (suppressions)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from gilgamesh.rules import RuleConfigService, RuleParamError, SuppressionField
from gilgamesh.web.auth import Session
from gilgamesh.web.deps import read_form, require_session, templates, verify_csrf

router = APIRouter()


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Detection rules: toggle each built-in rule and set its typed parameters."""
    return _rules_page(request, session)


@router.post("/rules/toggle", dependencies=[Depends(verify_csrf)])
async def rules_toggle(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Enable or disable one rule.

    Two clients, one write. A browser with htmx posts here and gets back just the
    control it clicked (``_rule_toggle.html``), which htmx swaps in place; a browser
    without JavaScript posts the same form and gets the whole page back with a notice.
    The rule is saved before either response is chosen, so both clients see the same
    state.
    """
    service: RuleConfigService = request.app.state.rules
    form = await read_form(request)
    rule_id = form.get("rule_id", "")
    enabled = form.get("enabled", "1") in {"1", "true", "yes", "on"}
    try:
        service.set_enabled(rule_id, enabled)
    except RuleParamError as exc:
        if _is_htmx(request):
            # htmx does not swap error responses, so the control keeps showing the state
            # that is actually stored; nothing is silently misreported.
            return HTMLResponse(f"Not saved: {exc}", status_code=422)
        return _rules_page(request, session, notice=f"Not saved: {exc}")
    if _is_htmx(request):
        return _rule_toggle_fragment(request, session, rule_id)
    state = "enabled" if enabled else "disabled"
    return _rules_page(request, session, notice=f"{rule_id} {state}.")


@router.post("/rules/params", dependencies=[Depends(verify_csrf)])
async def rules_params(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Save typed parameters for one rule."""
    service: RuleConfigService = request.app.state.rules
    form = await read_form(request)
    rule_id = form.get("rule_id", "")
    # Every parameter belonging to this rule is submitted together; anything else
    # in the form is ignored by the validator rather than trusted.
    submitted = {key: value for key, value in form.items() if key != "rule_id"}
    submitted.pop("csrf_token", None)
    try:
        service.set_params(rule_id, submitted)
    except RuleParamError as exc:
        return _rules_page(request, session, notice=f"Not saved: {exc}")
    return _rules_page(request, session, notice=f"Saved {rule_id}.")


@router.get("/suppressions", response_class=HTMLResponse)
async def suppressions_page(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """The allowlist: sources whose events are ignored."""
    return _suppressions_page(request, session)


@router.post("/suppressions", dependencies=[Depends(verify_csrf)])
async def suppressions_add(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Add an allowlist entry."""
    service: RuleConfigService = request.app.state.rules
    form = await read_form(request)
    try:
        field_name = SuppressionField(form.get("field", "").strip())
    except ValueError:
        return _suppressions_page(request, session, error="Choose what to match on.")
    try:
        service.add_suppression(
            form.get("rule_id", ""),
            field_name,
            form.get("value", ""),
            form.get("note", ""),
        )
    except RuleParamError as exc:
        return _suppressions_page(request, session, error=f"Not saved: {exc}")
    return _suppressions_page(request, session, notice="Allowlist entry added.")


@router.post("/suppressions/delete", dependencies=[Depends(verify_csrf)])
async def suppressions_delete(
    request: Request, session: Annotated[Session, Depends(require_session)]
) -> Response:
    """Remove an allowlist entry."""
    service: RuleConfigService = request.app.state.rules
    form = await read_form(request)
    try:
        service.remove_suppression(int(form.get("id", "0")))
    except (RuleParamError, ValueError) as exc:
        return _suppressions_page(request, session, error=f"Not removed: {exc}")
    return _suppressions_page(request, session, notice="Allowlist entry removed.")


def _is_htmx(request: Request) -> bool:
    """Whether the request came from htmx (it sets this header on every request)."""
    return request.headers.get("HX-Request", "").lower() == "true"


def _rule_item(request: Request, rule_id: str) -> dict[str, object]:
    """The context one rule control needs, in the shape ``rules.html`` renders."""
    service: RuleConfigService = request.app.state.rules
    definition = service.catalogue.require(rule_id)
    return {"definition": definition, "setting": service.settings()[definition.id]}


def _rule_toggle_fragment(request: Request, session: Session, rule_id: str) -> Response:
    """Render just one rule's toggle, for an htmx swap."""
    return templates.TemplateResponse(
        request=request,
        name="_rule_toggle.html",
        context={"session": session, "item": _rule_item(request, rule_id)},
    )


def _rules_page(request: Request, session: Session, notice: str = "") -> Response:
    """Render the detection rules page."""
    service: RuleConfigService = request.app.state.rules
    settings = service.settings()
    return templates.TemplateResponse(
        request=request,
        name="rules.html",
        context={
            "session": session,
            "rules": [
                {"definition": definition, "setting": settings[definition.id]}
                for definition in service.catalogue.definitions()
            ],
            "notice": notice,
        },
    )


def _suppressions_page(
    request: Request, session: Session, notice: str = "", error: str = ""
) -> Response:
    """Render the allowlist page."""
    service: RuleConfigService = request.app.state.rules
    return templates.TemplateResponse(
        request=request,
        name="suppressions.html",
        context={
            "session": session,
            "catalogue": service.catalogue,
            "suppressions": service.suppressions(),
            "notice": notice,
            "error": error,
        },
    )
