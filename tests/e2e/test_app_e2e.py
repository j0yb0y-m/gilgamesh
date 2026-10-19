"""Gilgamesh end to end: the owner's first session, in a real Chrome.

These are the flows a new owner performs, driven through the system browser
against a real server process (fixture in ``conftest.py``). They are a smoke
suite, not an alternative to the unit tests: hermetic behaviour stays in
``tests/test_*.py``; what belongs here is only what breaks between layers —
templates, routes, cookies, and static assets working together.

The tests share one server and therefore one fresh database, and they run in
file order: the wizard test creates the admin every later test signs in as.
Run the file whole::

    uv run pytest tests/e2e -m e2e --browser-channel chrome
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import RunningServer
from playwright.sync_api import Page, expect

from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity

pytestmark = pytest.mark.e2e

USERNAME = "admin"
#: Meets the policy (a 20+ character passphrase needs fewer character classes).
PASSWORD = "gilgamesh end-to-end passphrase 2026"


def sign_in(page: Page, app_url: str) -> None:
    """Authenticate through the real login form."""
    page.goto(f"{app_url}/login")
    page.get_by_label("Username").fill(USERNAME)
    page.get_by_label("Password").fill(PASSWORD)
    page.get_by_role("button", name="Sign in").click()
    expect(page).to_have_url(f"{app_url}/")


# --- first run ----------------------------------------------------------------


def test_first_run_wizard_creates_the_admin_and_lands_on_dashboard(
    page: Page, app_url: str, setup_token: str
) -> None:
    page.goto(f"{app_url}/")
    expect(page).to_have_url(f"{app_url}/setup")

    page.get_by_label("Setup token").fill(setup_token)
    page.get_by_label("Administrator username").fill(USERNAME)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Create account").click()

    expect(page).to_have_url(f"{app_url}/")
    expect(page.get_by_role("heading", name="Recent activity")).to_be_visible()
    expect(page.get_by_role("button", name="Sign out")).to_be_visible()


def test_login_rejects_a_wrong_password(page: Page, app_url: str) -> None:
    page.goto(f"{app_url}/login")
    page.get_by_label("Username").fill(USERNAME)
    page.get_by_label("Password").fill("not the real password at all")
    page.get_by_role("button", name="Sign in").click()

    expect(page.get_by_role("alert")).to_contain_text("Incorrect username or password.")
    expect(page).to_have_url(f"{app_url}/login")


def test_signing_out_and_back_in(page: Page, app_url: str) -> None:
    sign_in(page, app_url)
    page.get_by_role("button", name="Sign out").click()
    expect(page).to_have_url(f"{app_url}/login")

    sign_in(page, app_url)
    expect(page.get_by_role("heading", name="Recent activity")).to_be_visible()


# --- dashboard ----------------------------------------------------------------


def test_dashboard_shows_health_tiles_and_the_empty_feed(page: Page, app_url: str) -> None:
    sign_in(page, app_url)

    expect(page.locator("#tiles")).to_contain_text("Alerts today")
    # Nothing has been detected yet on this fresh box, and the app must say so
    # rather than invent an event: an empty feed is the honest state.
    expect(page.locator("#live-feed")).to_contain_text("Nothing recorded yet")


def test_a_detected_event_reaches_the_live_feed_over_sse(
    page: Page, app_url: str, server_log: Path
) -> None:
    """The whole live path: sensor-style DB write → delivery loop → SSE → DOM.

    The sensor is a separate process writing to SQLite; this writes the same way (the
    project's own ``Database``/``Event`` on the shared data directory) and waits for
    the browser to receive it without a reload. If delivery or the client script
    regresses, this is the test that says so.
    """
    sign_in(page, app_url)
    page.goto(f"{app_url}/")

    database = Database(server_log.parent / "gilgamesh.db")
    try:
        database.insert_event(
            Event(
                type=EventType.ARP_SPOOF,
                severity=Severity.HIGH,
                detector="arp",
                summary="e2e: gateway MAC changed",
                src_mac="aa:bb:cc:dd:ee:ff",
                src_ip="10.0.0.66",
            )
        )
    finally:
        database.close()

    newest = page.locator("#live-feed li.event").first
    expect(newest).to_contain_text("e2e: gateway MAC changed")
    expect(newest).to_have_attribute("data-severity", "high")


# --- rules --------------------------------------------------------------------


def test_ruling_a_rule_on_and_off_without_a_page_reload(page: Page, app_url: str) -> None:
    """The toggle is an htmx post: the control is swapped, the page is not.

    This is the browser half of ``test_rules_ui.py``'s fragment contract — it fails if
    htmx is missing, misconfigured (CSP, wrong swap target), or if the swapped control
    stops working.
    """
    sign_in(page, app_url)
    page.goto(f"{app_url}/rules")

    first_rule = page.locator("article.rule").first
    rule_id = first_rule.get_attribute("data-rule-id")
    assert rule_id, "rule templates must expose data-rule-id"
    state_before = first_rule.locator("span.state").inner_text().strip()

    first_rule.locator("form[action='/rules/toggle'] button").click()

    state = page.locator(f"article.rule[data-rule-id='{rule_id}'] span.state")
    expect(state).to_have_text("off" if state_before == "on" else "on")
    expect(page).to_have_url(f"{app_url}/rules")  # no navigation happened

    # The swapped-in control must still be live, not dead markup.
    page.locator(
        f"article.rule[data-rule-id='{rule_id}'] form[action='/rules/toggle'] button"
    ).click()
    expect(state).to_have_text(state_before)


def test_the_live_feed_can_be_paused_and_resumed(page: Page, app_url: str) -> None:
    """Alpine's CSP build must initialise under the real Content-Security-Policy.

    If Alpine fails to load (or a component expression is illegal in the CSP build) the
    server-rendered labels never change, so this test fails loudly instead of the button
    quietly doing nothing.
    """
    sign_in(page, app_url)
    page.goto(f"{app_url}/")

    state = page.locator("#feed-state")
    toggle = page.locator("#feed-toggle")
    expect(state).to_have_text("Live")

    toggle.click()

    expect(state).to_have_text("Paused")
    expect(toggle).to_contain_text("Resume live feed")

    toggle.click()

    expect(state).to_have_text("Live")
    expect(toggle).to_contain_text("Pause live feed")


def test_the_browser_reports_no_script_errors_or_csp_violations(page: Page, app_url: str) -> None:
    """The strict CSP is only useful if the vendored scripts actually work under it."""
    violations: list[str] = []
    page.on(
        "console",
        lambda message: (
            violations.append(message.text)
            if "Content Security Policy" in message.text or "Refused to" in message.text
            else None
        ),
    )
    page.on("pageerror", lambda error: violations.append(f"uncaught: {error}"))

    sign_in(page, app_url)
    page.goto(f"{app_url}/")
    page.locator("#feed-toggle").click()  # exercise Alpine
    page.goto(f"{app_url}/rules")
    page.locator("article.rule").first.locator(
        "form[action='/rules/toggle'] button"
    ).click()  # htmx
    page.wait_for_timeout(500)

    assert violations == []


# --- notifications ------------------------------------------------------------


def test_saving_a_webhook_configures_the_card_and_never_echoes_the_secret(
    page: Page, app_url: str
) -> None:
    sign_in(page, app_url)
    page.goto(f"{app_url}/notifications")

    card = page.locator("#channel-discord")
    card.get_by_label("Webhook URL").fill("http://127.0.0.1:9/hooks/e2e-fake")
    card.get_by_role("button", name="Save").click()

    expect(page.get_by_role("status")).to_contain_text("discord saved.")
    expect(card.get_by_text("configured", exact=True)).to_be_visible()
    # The stored secret must not be readable from the page.
    expect(card.get_by_label("Webhook URL")).to_have_value("")


def test_one_sided_quiet_hours_is_rejected(page: Page, app_url: str) -> None:
    sign_in(page, app_url)
    page.goto(f"{app_url}/notifications")

    card = page.locator("#channel-discord")
    card.get_by_label("Quiet from").fill("22:00")
    card.get_by_role("button", name="Save").click()

    expect(page.get_by_role("alert")).to_contain_text("set both quiet-hour ends, or neither")


# --- settings -----------------------------------------------------------------


def test_saving_settings_persists_after_a_reload(page: Page, app_url: str) -> None:
    sign_in(page, app_url)
    page.goto(f"{app_url}/settings")

    retention = page.get_by_label("Keep alerts for (days)")
    expect(retention).to_have_value("30")
    retention.fill("14")
    page.get_by_role("button", name="Save").click()

    expect(page.get_by_role("status")).to_contain_text("Settings saved.")
    page.reload()
    expect(page.get_by_label("Keep alerts for (days)")).to_have_value("14")


# --- health -------------------------------------------------------------------


def test_health_page_renders_the_report_and_rule_controls(page: Page, app_url: str) -> None:
    sign_in(page, app_url)
    page.goto(f"{app_url}/health")

    expect(page.get_by_role("heading", name="System health")).to_be_visible()
    for section in ("CPU", "Memory", "Disk", "Interfaces", "Detection rules"):
        expect(page.get_by_role("heading", name=section)).to_be_visible()
    expect(page.get_by_role("button", name="Update rules now")).to_be_enabled()


# --- shutdown (must stay last: it stops the server the other tests share) ------


def test_the_server_stops_promptly_with_a_dashboard_open(
    page: Page, app_url: str, server: RunningServer
) -> None:
    """SIGTERM is not allowed to be swallowed by an open server-sent-event stream.

    Uvicorn waits for in-flight request tasks *before* running the application's lifespan
    shutdown, and an SSE stream is a request that never completes on its own — so without
    the bound configured in ``gilgamesh.web.server`` this process would still be alive
    minutes later, and systemd would eventually SIGKILL it. The regression showed up
    exactly here: a real browser holding /events/stream open.
    """
    sign_in(page, app_url)
    page.goto(f"{app_url}/")
    expect(page.locator("#feed-state")).to_have_text("Live")
    page.wait_for_timeout(1000)  # let the EventSource establish itself

    server.process.terminate()
    try:
        server.process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        server.process.kill()
        pytest.fail("gilgamesh-web did not exit within 15s of SIGTERM while a dashboard was open")
