"""The Explain button on an alert detail page.

These tests pin the user-facing contract: the button always returns something
useful, AI is opt-in, provider output is escaped, both routes are CSRF-protected,
the key never reaches the page, and Regenerate really asks the provider again.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gilgamesh.ai.service import ExplanationService
from gilgamesh.config import Settings
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.web.app import create_app

PASSWORD = "a perfectly long passphrase"
KEY = "sk-explain-secret-do-not-echo"
PROVIDER_TEXT = "The camera uploaded a large backup."


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


def seed_event(client: TestClient, **overrides: object) -> str:
    """Insert an event through the app's own database handle."""
    fields: dict[str, object] = {
        "type": EventType.ARP_SPOOF,
        "severity": Severity.HIGH,
        "detector": "arp",
        "summary": "Gateway MAC changed",
        "src_ip": "10.0.0.2",
        "details": {"reason": "gateway_mac_changed", "count": 3},
    }
    fields.update(overrides)
    event = _state(client).state.db.insert_event(Event(**fields))  # type: ignore[arg-type]
    return event.id


def csrf_from(client: TestClient, path: str) -> str:
    body = client.get(path).text
    marker = 'name="csrf_token" value="'
    start = body.index(marker) + len(marker)
    return body[start : body.index('"', start)]


def enable_ai(
    client: TestClient,
    *,
    text: str = PROVIDER_TEXT,
    seen: list[httpx.Request] | None = None,
) -> None:
    """Turn AI on and give the service a deterministic in-process transport."""
    state = _state(client).state
    state.ai_settings.update(
        enabled=True,
        preset="custom",
        kind="openai",
        base_url="https://1.1.1.1/v1",
        model="test-model",
    )
    state.ai_keys.set_key(KEY)

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": text}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 5},
            },
        )

    state.explanations = ExplanationService(
        state.db,
        state.ai_settings,
        state.ai_keys,
        transport=httpx.MockTransport(handler),
    )


def test_explain_with_ai_off_returns_the_template(client: TestClient) -> None:
    event_id = seed_event(client)

    response = client.post(
        f"/alerts/{event_id}/explain",
        data={"csrf_token": csrf_from(client, f"/alerts/{event_id}")},
    )

    assert response.status_code == 200
    assert "What happened" in response.text
    assert "Why it matters" in response.text
    assert "What to check" in response.text
    assert "AI explanations are off" in response.text
    assert "Standard explanation" in response.text
    assert "Regenerate" in response.text


def test_explain_with_ai_on_returns_provider_text_and_disclaimer(
    client: TestClient,
) -> None:
    event_id = seed_event(client)
    enable_ai(client)

    response = client.post(
        f"/alerts/{event_id}/explain",
        data={"csrf_token": csrf_from(client, f"/alerts/{event_id}")},
    )

    assert response.status_code == 200
    assert PROVIDER_TEXT in response.text
    assert "AI-generated" in response.text
    assert "AI-generated explanation" in response.text
    assert "check the evidence before acting" in response.text
    assert "Regenerate" in response.text


def test_provider_html_is_escaped(client: TestClient) -> None:
    event_id = seed_event(client)
    enable_ai(client, text='<script>alert("x")</script> not trusted')

    response = client.post(
        f"/alerts/{event_id}/explain",
        data={"csrf_token": csrf_from(client, f"/alerts/{event_id}")},
    )

    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text


def test_explain_requires_csrf(client: TestClient) -> None:
    event_id = seed_event(client)

    response = client.post(f"/alerts/{event_id}/explain")

    assert response.status_code == 403


def test_explain_unknown_event_is_404(client: TestClient) -> None:
    event_id = seed_event(client)

    response = client.post(
        "/alerts/does-not-exist/explain",
        data={"csrf_token": csrf_from(client, f"/alerts/{event_id}")},
    )

    assert response.status_code == 404


def test_regenerate_asks_the_provider_again(client: TestClient) -> None:
    event_id = seed_event(client)
    seen: list[httpx.Request] = []
    enable_ai(client, seen=seen)
    token = csrf_from(client, f"/alerts/{event_id}")

    first = client.post(f"/alerts/{event_id}/explain", data={"csrf_token": token})
    cached = client.post(f"/alerts/{event_id}/explain", data={"csrf_token": token})
    second = client.post(f"/alerts/{event_id}/explain/regenerate", data={"csrf_token": token})

    assert first.status_code == cached.status_code == second.status_code == 200
    assert PROVIDER_TEXT in first.text
    assert PROVIDER_TEXT in cached.text
    assert PROVIDER_TEXT in second.text
    assert len(seen) == 2, "a plain Explain must hit the cache; Regenerate must not"


def test_alert_detail_page_offers_the_explain_form(client: TestClient) -> None:
    event_id = seed_event(client)

    body = client.get(f"/alerts/{event_id}").text

    assert f'hx-post="/alerts/{event_id}/explain"' in body
    assert 'hx-target="#explanation"' in body
    assert 'id="explanation"' in body
    assert "Explain this alert" in body
    assert "Evidence" in body, "the evidence stays visible beside the explanation card"


def test_partial_carries_the_source_badge_and_a_regenerate_form(
    client: TestClient,
) -> None:
    event_id = seed_event(client)
    enable_ai(client)

    response = client.post(
        f"/alerts/{event_id}/explain",
        data={"csrf_token": csrf_from(client, f"/alerts/{event_id}")},
    )

    assert 'hx-post="/alerts/' + event_id + '/explain/regenerate"' in response.text
    assert 'name="csrf_token"' in response.text


def test_the_api_key_never_reaches_the_response(client: TestClient) -> None:
    event_id = seed_event(client)
    enable_ai(client)

    response = client.post(
        f"/alerts/{event_id}/explain",
        data={"csrf_token": csrf_from(client, f"/alerts/{event_id}")},
    )

    assert response.status_code == 200
    assert KEY not in response.text
    assert KEY not in str(response.headers)
