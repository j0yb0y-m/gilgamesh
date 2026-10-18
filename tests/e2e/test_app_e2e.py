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

import pytest
from playwright.sync_api import Page, expect

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
    page: Page, app_url: str
) -> None:
    page.goto(f"{app_url}/")
    expect(page).to_have_url(f"{app_url}/setup")

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


def test_dashboard_shows_health_tiles_and_the_seeded_event(page: Page, app_url: str) -> None:
    sign_in(page, app_url)

    expect(page.locator("#tiles")).to_contain_text("Alerts today")
    # The walking-skeleton detector seeds one event at start-up, so the feed is
    # never empty on a fresh box. (Create_app seeds it; if this regresses, the
    # dashboard would silently show nothing.)
    expect(page.locator("#live-feed li.event").first).to_be_visible()


# --- rules --------------------------------------------------------------------


def test_ruling_a_rule_on_and_off(page: Page, app_url: str) -> None:
    sign_in(page, app_url)
    page.goto(f"{app_url}/rules")

    first_rule = page.locator("article.rule").first
    rule_id = first_rule.get_attribute("data-rule-id")
    assert rule_id, "rule templates must expose data-rule-id"
    state_before = first_rule.locator("span.state").inner_text().strip()

    first_rule.locator("form[action='/rules/toggle'] button").click()

    expect(page.get_by_role("status")).to_be_visible()
    state_after = page.locator(f"article.rule[data-rule-id='{rule_id}'] span.state")
    expect(state_after).to_have_text("off" if state_before == "on" else "on")


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
