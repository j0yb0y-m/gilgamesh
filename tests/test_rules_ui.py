"""M11 — rules and allowlist HTTP surface tests.

The service layer is tested in ``test_rules.py``; these tests check that the routes are
reachable only with a session, that every state change is CSRF-protected, and that
invalid input comes back as a message rather than a stack trace.
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
from gilgamesh.web.app import create_app

PASSWORD = "a perfectly long passphrase"


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


def csrf_from(client: TestClient, path: str) -> str:
    """Read the session's CSRF token out of a rendered page."""
    body = client.get(path).text
    marker = 'name="csrf_token" value="'
    start = body.index(marker) + len(marker)
    return body[start : body.index('"', start)]


def test_rules_page_requires_a_session(client: TestClient) -> None:
    client.cookies.clear()

    response = client.get("/rules", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_rules_page_lists_every_rule(client: TestClient) -> None:
    response = client.get("/rules")

    assert response.status_code == 200
    assert "arp.gateway_mac_changed" in response.text
    assert "scan.vertical" in response.text


def test_rules_toggle_requires_csrf(client: TestClient) -> None:
    response = client.post("/rules/toggle", data={"rule_id": "arp.ip_mac_conflict", "enabled": "0"})

    assert response.status_code == 403


def test_rules_can_be_disabled_through_the_ui(client: TestClient) -> None:
    token = csrf_from(client, "/rules")

    response = client.post(
        "/rules/toggle",
        data={
            "csrf_token": token,
            "rule_id": "arp.ip_mac_conflict",
            "enabled": "0",
        },
    )

    assert response.status_code == 200
    assert "disabled" in response.text


def test_unknown_rule_toggle_is_refused_not_crashed(client: TestClient) -> None:
    token = csrf_from(client, "/rules")

    response = client.post(
        "/rules/toggle", data={"csrf_token": token, "rule_id": "made.up", "enabled": "0"}
    )

    assert response.status_code == 200
    assert "Not saved" in response.text


# --- the live toggle (htmx) ---------------------------------------------------
#
# The Rules page works without JavaScript (a plain form post) and gets better with it
# (the same post answered with just the control, which htmx swaps in place). These tests
# pin both halves: the markup that instructs htmx, and the fragment the route returns.


def test_the_rules_page_asks_htmx_to_swap_the_control_in_place(client: TestClient) -> None:
    body = client.get("/rules").text

    assert 'hx-post="/rules/toggle"' in body
    assert 'hx-target="this"' in body
    assert 'hx-swap="outerHTML"' in body
    # The no-JavaScript fallback must survive: same URL, plain form semantics.
    assert 'method="post"' in body
    assert 'action="/rules/toggle"' in body


def test_an_htmx_toggle_returns_only_the_control(client: TestClient) -> None:
    token = csrf_from(client, "/rules")

    response = client.post(
        "/rules/toggle",
        data={"csrf_token": token, "rule_id": "arp.ip_mac_conflict", "enabled": "0"},
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 200
    assert "<html" not in response.text  # a fragment, not a page
    assert 'id="toggle-arp.ip_mac_conflict"' in response.text
    # The swapped control must offer the opposite action and report the new state.
    assert 'value="1"' in response.text
    # The state span is the contract the UI reads; whitespace around the text is
    # formatting, so match the element rather than an exact column.
    assert re.search(r'<span class="state[^"]*">\s*off\s*</span>', response.text)


def test_a_second_htmx_toggle_restores_the_rule(client: TestClient) -> None:
    token = csrf_from(client, "/rules")
    headers = {"HX-Request": "true"}

    client.post(
        "/rules/toggle",
        data={"csrf_token": token, "rule_id": "arp.ip_mac_conflict", "enabled": "0"},
        headers=headers,
    )
    response = client.post(
        "/rules/toggle",
        data={"csrf_token": token, "rule_id": "arp.ip_mac_conflict", "enabled": "1"},
        headers=headers,
    )

    assert re.search(r'<span class="state[^"]*">\s*on\s*</span>', response.text)
    assert 'value="0"' in response.text


def test_an_htmx_toggle_of_an_unknown_rule_is_an_error_status(client: TestClient) -> None:
    """htmx does not swap error responses, so a bad request cannot fake a state change."""
    token = csrf_from(client, "/rules")

    response = client.post(
        "/rules/toggle",
        data={"csrf_token": token, "rule_id": "made.up", "enabled": "0"},
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 422
    assert "Not saved" in response.text


def test_an_htmx_toggle_without_csrf_is_refused(client: TestClient) -> None:
    response = client.post(
        "/rules/toggle",
        data={"rule_id": "arp.ip_mac_conflict", "enabled": "0"},
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 403


def test_threshold_save_accepts_a_valid_value(client: TestClient) -> None:
    token = csrf_from(client, "/rules")

    response = client.post(
        "/rules/params",
        data={"csrf_token": token, "rule_id": "scan.vertical", "port_threshold": "35"},
    )

    assert response.status_code == 200
    assert "Saved scan.vertical" in response.text
    assert 'value="35"' in response.text


def test_threshold_save_rejects_out_of_range(client: TestClient) -> None:
    token = csrf_from(client, "/rules")

    response = client.post(
        "/rules/params",
        data={"csrf_token": token, "rule_id": "scan.vertical", "port_threshold": "99999"},
    )

    assert response.status_code == 200
    assert "Not saved" in response.text
    # The previous value must survive a rejected save.
    assert 'value="20"' in response.text


def test_threshold_save_rejects_a_non_numeric_value(client: TestClient) -> None:
    token = csrf_from(client, "/rules")

    response = client.post(
        "/rules/params",
        data={"csrf_token": token, "rule_id": "scan.vertical", "port_threshold": "abc"},
    )

    assert response.status_code == 200
    assert "Not saved" in response.text


def test_suppressions_page_requires_a_session(client: TestClient) -> None:
    client.cookies.clear()

    assert client.get("/suppressions", follow_redirects=False).status_code == 303


def test_allowlist_entry_can_be_added(client: TestClient) -> None:
    token = csrf_from(client, "/suppressions")

    response = client.post(
        "/suppressions",
        data={
            "csrf_token": token,
            "rule_id": "arp.gateway_mac_changed",
            "field": "src_mac",
            "value": "DE:AD:BE:EF:00:01",
            "note": "test device",
        },
    )

    assert response.status_code == 200
    assert "Allowlist entry added" in response.text
    assert "de:ad:be:ef:00:01" in response.text


def test_allowlist_rejects_a_malformed_value(client: TestClient) -> None:
    token = csrf_from(client, "/suppressions")

    response = client.post(
        "/suppressions",
        data={
            "csrf_token": token,
            "rule_id": "arp.gateway_mac_changed",
            "field": "src_mac",
            "value": "not-a-mac",
        },
    )

    assert response.status_code == 200
    assert "Not saved" in response.text


def test_allowlist_rejects_an_unknown_match_field(client: TestClient) -> None:
    token = csrf_from(client, "/suppressions")

    response = client.post(
        "/suppressions",
        data={
            "csrf_token": token,
            "rule_id": "arp.gateway_mac_changed",
            "field": "regex",
            "value": ".*",
        },
    )

    assert response.status_code == 200
    assert "Match on" in response.text


def test_allowlist_entry_can_be_removed(client: TestClient) -> None:
    token = csrf_from(client, "/suppressions")
    client.post(
        "/suppressions",
        data={
            "csrf_token": token,
            "rule_id": "arp.gateway_mac_changed",
            "field": "src_mac",
            "value": "de:ad:be:ef:00:01",
        },
    )

    response = client.post("/suppressions/delete", data={"csrf_token": token, "id": "1"})

    assert response.status_code == 200
    assert "No allowlist entries yet" in response.text


def test_suppression_delete_requires_csrf(client: TestClient) -> None:
    assert client.post("/suppressions/delete", data={"id": "1"}).status_code == 403


def test_rules_state_survives_a_restart(client: TestClient, tmp_path: Path) -> None:
    """The database is the source of truth, so settings outlive the process."""
    token = csrf_from(client, "/rules")
    client.post(
        "/rules/params",
        data={"csrf_token": token, "rule_id": "scan.vertical", "port_threshold": "42"},
    )

    with TestClient(create_app(Settings(data_dir=tmp_path))) as restarted:
        session_cookie = client.cookies.get("gilgamesh_session")
        assert session_cookie is not None
        restarted.cookies.set("gilgamesh_session", session_cookie)
        assert 'value="42"' in restarted.get("/rules").text
