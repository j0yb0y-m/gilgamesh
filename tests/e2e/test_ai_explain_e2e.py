"""End-to-end: explain an alert with a local fake provider, then turn AI off.

The provider is a throwaway ``ThreadingHTTPServer`` on loopback that speaks the
OpenAI-compatible shape. This test proves the whole opt-in path in a real browser:
the owner enters the key through the web UI, the key never comes back, htmx swaps
the explanation in, and disabling AI returns the deterministic template even though
a cached AI answer exists.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import RunningServer, read_setup_token, running_server
from playwright.sync_api import Page, expect

from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity

pytestmark = pytest.mark.e2e

USERNAME = "admin"
PASSWORD = "gilgamesh ai end-to-end passphrase"
KEY = "sk-fake-e2e-do-not-echo"
NARRATIVE = "The device uploaded a large backup at an unusual hour."


class _FakeProviderHandler(BaseHTTPRequestHandler):
    """Answer every chat-completions request with the same fixed narrative."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        body = json.dumps(
            {
                "choices": [{"message": {"content": NARRATIVE}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


@pytest.fixture
def fake_provider() -> Iterator[str]:
    """Run the fake provider on a free loopback port for one test."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeProviderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{int(server.server_address[1])}/v1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def ai_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningServer]:
    """An isolated real server, so this file does not depend on collection order."""
    data_dir = tmp_path_factory.mktemp("gilgamesh-ai-e2e")
    with running_server(data_dir, data_dir / "server.log") as running:
        yield running


def seed_alert(server: RunningServer) -> str:
    """Write an alert the same way the sensor process does."""
    database = Database(server.log_path.parent / "gilgamesh.db")
    try:
        event = database.insert_event(
            Event(
                type=EventType.ARP_SPOOF,
                severity=Severity.HIGH,
                detector="arp",
                summary="e2e: gateway MAC changed",
                src_mac="aa:bb:cc:dd:ee:ff",
                src_ip="10.0.0.66",
                details={"reason": "gateway_mac_changed", "count": 2},
            )
        )
        return event.id
    finally:
        database.close()


def test_explain_with_a_local_fake_provider_then_disable_it(
    page: Page, ai_server: RunningServer, fake_provider: str
) -> None:
    page.goto(f"{ai_server.url}/")
    expect(page).to_have_url(f"{ai_server.url}/setup")
    page.get_by_label("Setup token").fill(read_setup_token(ai_server.log_path))
    page.get_by_label("Administrator username").fill(USERNAME)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Create account").click()
    expect(page).to_have_url(f"{ai_server.url}/")

    alert_id = seed_alert(ai_server)

    page.goto(f"{ai_server.url}/settings")
    page.get_by_label("Provider preset").select_option("custom")
    page.get_by_label("Model").fill("fake")
    page.get_by_label("Base URL").fill(fake_provider)
    page.get_by_label("API key").fill(KEY)
    page.get_by_label("Local provider (allow HTTP and private addresses)").check()
    page.get_by_label("Enable AI explanations").check()
    page.get_by_role("button", name="Save AI settings").click()

    expect(page.get_by_role("status")).to_contain_text("AI settings saved.")
    assert KEY not in page.content(), "the key is write-only and must not be echoed"

    page.goto(f"{ai_server.url}/alerts/{alert_id}")
    page.get_by_role("button", name="Explain this alert").click()
    explanation = page.locator("#explanation")
    expect(explanation).to_contain_text(NARRATIVE)
    expect(explanation).to_contain_text("AI-generated explanation")
    expect(explanation).to_contain_text("Regenerate")

    page.goto(f"{ai_server.url}/settings")
    page.get_by_label("Enable AI explanations").uncheck()
    page.get_by_role("button", name="Save AI settings").click()
    expect(page.get_by_role("status")).to_contain_text("AI settings saved.")

    page.goto(f"{ai_server.url}/alerts/{alert_id}")
    page.get_by_role("button", name="Explain this alert").click()
    expect(explanation).to_contain_text("What happened")
    expect(explanation).to_contain_text("AI explanations are off")
