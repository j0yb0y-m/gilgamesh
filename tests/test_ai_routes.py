"""The AI settings card and its write-only key handling.

The card is the only place the owner enters a provider key. These tests pin the
promises that matter: the key is never echoed or audited, a blank field means
"unchanged", "Test connection" does not save, invalid values leave the stored
settings untouched, and every route is CSRF-protected.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gilgamesh.ai.providers import MAX_RESPONSE_BYTES
from gilgamesh.config import Settings
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.web.app import create_app

PASSWORD = "a perfectly long passphrase"
KEY = "sk-secret-123-do-not-echo"
REPO_ROOT = Path(__file__).resolve().parents[1]


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


def _state(client: TestClient) -> FastAPI:
    return cast(FastAPI, client.app)


def csrf_from(client: TestClient, path: str) -> str:
    body = client.get(path).text
    marker = 'name="csrf_token" value="'
    start = body.index(marker) + len(marker)
    return body[start : body.index('"', start)]


def payload(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "enabled": "1",
        "preset": "custom",
        "kind": "openai",
        "base_url": "https://1.1.1.1/v1",
        "model": "test-model",
        "max_tokens": "400",
        "timeout_s": "20",
        "redact_mac": "1",
        "redact_hostname": "1",
        "redact_ips": "1",
    }
    values.update(overrides)
    return values


def save(client: TestClient, **overrides: object) -> None:
    response = client.post(
        "/settings/ai",
        data={"csrf_token": csrf_from(client, "/settings"), **payload(**overrides)},
        follow_redirects=False,
    )
    assert response.status_code == 303


def openai_transport(seen: dict[str, str | None] | None = None) -> httpx.MockTransport:
    def handler(incoming: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen["auth"] = incoming.headers.get("authorization")
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "OK"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 1},
            },
        )

    return httpx.MockTransport(handler)


def test_ai_settings_save_is_write_only_and_never_echoes_the_key(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        save(client, api_key=KEY)

    body = client.get("/settings").text
    state = _state(client).state
    assert KEY not in body
    assert KEY not in str(client.get("/settings").headers)
    assert "API key is set" in body
    assert "AI explanations are optional" in body
    saved = state.ai_settings.get()
    assert saved.enabled is True
    assert saved.preset == "custom"
    assert saved.base_url == "https://1.1.1.1/v1"
    assert saved.model == "test-model"
    assert state.ai_keys.get_key() == KEY
    actions = [row["action"] for row in state.db.audit_entries()]
    assert any("AI settings updated" in action for action in actions)
    assert all(KEY not in action for action in actions)
    assert KEY not in caplog.text


def test_blank_key_keeps_stored_key_and_clear_removes_it(client: TestClient) -> None:
    save(client, api_key=KEY)

    save(client, api_key="")

    assert _state(client).state.ai_keys.get_key() == KEY

    response = client.post(
        "/settings/ai/key/clear",
        data={"csrf_token": csrf_from(client, "/settings")},
        follow_redirects=False,
    )

    assert response.status_code == 303
    state = _state(client).state
    assert state.ai_keys.is_set() is False
    assert state.ai_keys.get_key() is None
    body = client.get("/settings").text
    assert "API key is not set" in body
    actions = [row["action"] for row in state.db.audit_entries()]
    assert any("AI API key cleared" in action for action in actions)


def test_test_connection_reports_model_and_latency_without_saving(client: TestClient) -> None:
    seen: dict[str, str | None] = {}
    _state(client).state.ai_transport = openai_transport(seen)

    response = client.post(
        "/settings/ai/test",
        data={"csrf_token": csrf_from(client, "/settings"), **payload(api_key=KEY)},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Connection OK: test-model in" in response.text
    assert " ms" in response.text
    assert KEY not in response.text
    assert seen["auth"] == f"Bearer {KEY}"
    state = _state(client).state
    assert state.ai_settings.get().enabled is False
    assert state.ai_settings.get().base_url == "https://api.openai.com/v1"
    assert state.ai_keys.is_set() is False


def test_test_connection_uses_the_stored_key_when_blank(client: TestClient) -> None:
    save(client, api_key=KEY)
    seen: dict[str, str | None] = {}
    _state(client).state.ai_transport = openai_transport(seen)

    response = client.post(
        "/settings/ai/test",
        data={"csrf_token": csrf_from(client, "/settings"), **payload(api_key="")},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Connection OK: test-model in" in response.text
    assert seen["auth"] == f"Bearer {KEY}"


def test_invalid_url_is_rejected_and_not_saved(client: TestClient) -> None:
    response = client.post(
        "/settings/ai",
        data={
            "csrf_token": csrf_from(client, "/settings"),
            **payload(base_url="http://api.example/v1"),
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Not saved" in response.text
    assert _state(client).state.ai_settings.get().base_url == "https://api.openai.com/v1"

    response = client.post(
        "/settings/ai",
        data={
            "csrf_token": csrf_from(client, "/settings"),
            **payload(base_url="https://169.254.169.254/v1", local_provider="1"),
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Not saved" in response.text


def test_invalid_numbers_leave_the_stored_settings_unchanged(client: TestClient) -> None:
    save(client, max_tokens="600", timeout_s="30")

    response = client.post(
        "/settings/ai",
        data={
            "csrf_token": csrf_from(client, "/settings"),
            **payload(max_tokens="5000", timeout_s="30"),
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Not saved" in response.text
    assert _state(client).state.ai_settings.get().max_tokens == 600

    response = client.post(
        "/settings/ai",
        data={
            "csrf_token": csrf_from(client, "/settings"),
            **payload(max_tokens="400", timeout_s="not-a-number"),
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Not saved" in response.text


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("/settings/ai", payload()),
        ("/settings/ai/test", payload()),
        ("/settings/ai/key/clear", {}),
    ],
)
def test_ai_routes_require_csrf(client: TestClient, path: str, data: dict[str, object]) -> None:
    assert client.post(path, data=data).status_code == 403


def test_ai_card_is_off_by_default_and_lists_the_presets(client: TestClient) -> None:
    body = client.get("/settings").text

    assert "AI explanations are optional" in body
    assert "redacted summary leaves this device" in body
    assert "API key is not set" in body
    for label in (
        "OpenAI",
        "Anthropic",
        "Google Gemini",
        "Groq",
        "Mistral",
        "OpenRouter",
        "Ollama (local)",
        "llama.cpp (local)",
        "Custom",
    ):
        assert label in body
    assert "Test connection" in body


def test_preset_options_carry_defaults_for_the_client_fill(client: TestClient) -> None:
    body = client.get("/settings").text

    assert "data-ai-preset" in body
    assert 'data-base-url="https://api.openai.com/v1"' in body
    assert 'data-model="llama3.2"' in body
    assert 'data-local="1"' in body
    script = (REPO_ROOT / "static/js/app.js").read_text(encoding="utf-8")
    assert "data-ai-preset" in script


def test_key_file_loss_is_visible_without_pretending_the_key_works(client: TestClient) -> None:
    save(client, api_key=KEY)
    _state(client).state.settings.ai_key_path.unlink()

    body = client.get("/settings").text

    assert "API key is set but cannot be read" in body
    assert "API key is set<" not in body


def test_connection_failure_is_safe_and_never_includes_the_key(client: TestClient) -> None:
    def handler(incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "bad key"})

    _state(client).state.ai_transport = httpx.MockTransport(handler)

    response = client.post(
        "/settings/ai/test",
        data={"csrf_token": csrf_from(client, "/settings"), **payload(api_key=KEY)},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Connection failed: authentication failed" in response.text
    assert KEY not in response.text


def test_oversized_probe_response_is_reported_safely(client: TestClient) -> None:
    def handler(incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))

    _state(client).state.ai_transport = httpx.MockTransport(handler)

    response = client.post(
        "/settings/ai/test",
        data={"csrf_token": csrf_from(client, "/settings"), **payload(api_key=KEY)},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Connection failed: response too large" in response.text


def seed_alert(client: TestClient, **overrides: object) -> str:
    """Insert one alert with identifiers in a whitelisted fact."""
    fields: dict[str, object] = {
        "type": EventType.ARP_SPOOF,
        "severity": Severity.HIGH,
        "detector": "arp",
        "summary": "Gateway MAC changed",
        "src_mac": "aa:bb:cc:dd:ee:01",
        "src_ip": "10.0.0.20",
        "details": {"reason": "latest-event-reason", "count": 77},
    }
    fields.update(overrides)
    event = _state(client).state.db.insert_event(Event(**fields))  # type: ignore[arg-type]
    return event.id


def test_preview_shows_redacted_json_and_no_identifiers(client: TestClient) -> None:
    seed_alert(
        client,
        details={
            "reason": "gateway aa:bb:cc:dd:ee:01 at 10.0.0.20 changed",
            "count": 77,
        },
    )

    body = client.get("/settings").text

    assert "Preview what will be sent" in body
    tail = body.split("Preview what will be sent", 1)[1]
    assert "aa:bb:cc" not in tail
    assert "10.0.0.20" not in tail
    assert "[redacted mac]" in tail
    assert "[redacted ip]" in tail


def test_preview_uses_the_most_recent_event_and_says_when_there_is_none(
    client: TestClient,
) -> None:
    body = client.get("/settings").text
    assert "No alert to preview yet" in body

    seed_alert(client, details={"reason": "newest-event-reason", "count": 3})

    body = client.get("/settings").text

    assert "newest-event-reason" in body.split("Preview what will be sent", 1)[1]


def test_saving_a_key_is_audited_without_echoing_it(client: TestClient) -> None:
    save(client, api_key=KEY)

    actions = [row["action"] for row in _state(client).state.db.audit_entries()]

    assert any("AI API key set" in action for action in actions)
    assert all(KEY not in action for action in actions)
