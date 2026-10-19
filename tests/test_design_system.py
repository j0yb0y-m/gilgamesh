"""The UI design system.

The styling pass replaced the default-Tailwind vocabulary with a real design system:
severity plays the first fiddle (badge + row rule), the header is an instrument panel
with an active-page mark and a live chip, and every icon is inline SVG from one
vendored set. These tests pin the properties the visual design promises, so a future
edit cannot silently drop them — the browser is the only judge below this level, and
that judge is the Playwright end-to-end suite.

Every test here runs against the real routes and the real template files. The two
scan tests (licence table, inline `style=`) are guards rather than behaviour change:
each documents a constraint the breaks would be invisible in a code review — an
undeclared licence (C1) and a CSP violation (`style-src 'self'` bans the inline
`style=` attribute, not just `<style>` elements).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.web.app import create_app

PASSWORD = "a perfectly long passphrase"
REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = REPO_ROOT / "src/gilgamesh/web/templates"
ICONS = TEMPLATES / "_icons.html"
APP_CSS = REPO_ROOT / "static/css/app.css"

# Every page the nav advertises. `/` is the dashboard; the rest are first-class routes.
NAV_PATHS = (
    "/",
    "/alerts",
    "/devices",
    "/rules",
    "/suppressions",
    "/notifications",
    "/health",
    "/settings",
)

# Selectors the built CSS must contain for the design system to exist at all. A miss
# almost always means "a template was edited and app.css was not rebuilt". Regexes,
# because the committed build is formatted rather than minified.
REQUIRED_CSS = (
    r"\.badge\s*\{",
    r"\.badge-critical",
    r"\.badge-high",
    r"\.badge-medium",
    r"\.badge-low",
    r"\.badge-info",
    r"\[data-severity=\"critical\"\]",
    r"\[data-severity=\"high\"\]",
    r"\.nav-link",
    r"\.tile\s*\{",
    r"\.btn-primary",
    r"\.input\b",
    r"\.live-chip",
    r"\.empty-state",
)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as test_client:
        auth = cast(FastAPI, test_client.app).state.auth
        token = auth.ensure_setup_token()
        response = test_client.post(
            "/setup",
            data={"username": "admin", "password": PASSWORD, "setup_token": token},
            follow_redirects=False,
        )
        assert response.status_code == 303
        yield test_client


def seed_event(database_path: Path, **overrides: object) -> str:
    """Insert an event straight into the database so the UI has something to show."""
    database = Database(database_path)
    database.initialize()
    fields: dict[str, object] = {
        "type": EventType.ARP_SPOOF,
        "severity": Severity.HIGH,
        "detector": "arp",
        "summary": "Gateway MAC changed",
        "src_ip": "10.0.0.2",
    }
    fields.update(overrides)
    event = database.insert_event(Event(**fields))  # type: ignore[arg-type]
    database.close()
    return event.id


# --- the licence of the icon set -------------------------------------------------


def test_the_licence_table_records_the_icon_set() -> None:
    """C1: every vendored asset's licence is recorded before the asset is added."""
    text = (REPO_ROOT / "docs/research/12-licenses.md").read_text(encoding="utf-8")

    assert "Lucide" in text, "the icon set must appear in the licence table"
    assert "ISC" in text, "Lucide ships under ISC; that SPDX id must be recorded"
    assert "lucide-icons/lucide" in text, "the source URL must be recorded"


# --- the header: active page -----------------------------------------------------


@pytest.mark.parametrize("path", NAV_PATHS)
def test_the_nav_marks_the_active_page(client: TestClient, path: str) -> None:
    """Exactly one nav link is `aria-current="page"`, and it is the page you are on."""
    body = client.get(path).text

    assert body.count('aria-current="page"') == 1, "the active mark must be unique"
    link = re.search(rf'<a href="{re.escape(path)}"[^>]*aria-current="page"', body) or re.search(
        rf'<a[^>]*href="{re.escape(path)}"[^>]*aria-current="page"', body
    )
    assert link, f"on {path} the matching nav link must carry aria-current"


def test_the_nav_is_a_landmark_with_an_accessible_name(client: TestClient) -> None:
    body = client.get("/").text

    assert re.search(r"<nav\b[^>]*aria-label=", body), "the primary nav must be labelled"


# --- the severity system ---------------------------------------------------------


@pytest.mark.parametrize("level", [s.value for s in Severity], ids=[s.value for s in Severity])
def test_alert_rows_render_a_severity_badge(client: TestClient, tmp_path: Path, level: str) -> None:
    seed_event(tmp_path / "gilgamesh.db", severity=Severity(level), summary="probe")

    body = client.get("/alerts").text

    assert f"badge badge-{level}" in body, "every severity must have its badge class"
    assert f">{level}<" in body, "the level's name must still be readable as text"


def test_dashboard_feed_rows_render_severity_badges(client: TestClient, tmp_path: Path) -> None:
    seed_event(tmp_path / "gilgamesh.db", severity=Severity.CRITICAL, summary="burn")

    body = client.get("/").text

    assert "badge badge-critical" in body
    assert "data-event-id=" in body, "the live feed must keep its per-row identity"


# --- the built stylesheet --------------------------------------------------------


def test_app_css_is_built_for_the_design_system() -> None:
    css = APP_CSS.read_text(encoding="utf-8")

    assert len(css) > 1, "app.css must be the committed build, never empty"
    missing = [pattern for pattern in REQUIRED_CSS if re.search(pattern, css) is None]
    assert missing == [], f"rebuilt app.css must contain: {missing}"


# --- the icon macro --------------------------------------------------------------


def test_the_icon_sprite_defines_its_symbols(defined_icons: set[str]) -> None:
    """A typo'd icon renders nothing; the sprite is the single source of icon truth."""
    assert len(defined_icons) >= 20, "the committed icon set must be present"


@pytest.fixture
def defined_icons() -> set[str]:
    try:
        text = ICONS.read_text(encoding="utf-8")
    except FileNotFoundError:
        pytest.fail("_icons.html must exist: every icon is defined in one template")
    return {
        re.sub(r"^icon-", "", sid) for sid in re.findall(r"<symbol\b[^>]*\bid=\"([^\"]+)\"", text)
    }


@pytest.mark.parametrize("path", NAV_PATHS)
def test_rendered_pages_only_use_defined_icons(
    client: TestClient, path: str, defined_icons: set[str]
) -> None:
    """Icons are render-generated (the `icon()` macro); validate the DOM's real refs.

    Scanning templates for `#icon-…` finds nothing: the macro writes the href at
    render time, so the check has to run over rendered pages.
    """
    body = client.get(path).text
    used = set(re.findall(r'href="#icon-([\w-]+)"', body))

    assert used, f"{path} must render at least one resolved icon"
    undefined = sorted(used - defined_icons)
    assert undefined == [], f"{path} renders undefined icons: {undefined}"


# --- CSP guards ------------------------------------------------------------------


def test_no_template_renders_an_inline_style_attribute() -> None:
    """CSP guard: `style-src 'self'` also forbids `style=` attributes, not only <style>.
    The design system must express everything through classes."""
    offenders: list[str] = []
    for template in sorted(TEMPLATES.glob("*.html")):
        if re.search(r"\sstyle=", template.read_text(encoding="utf-8")):
            offenders.append(template.name)
    assert offenders == []
