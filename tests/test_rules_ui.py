"""M11 — rules and allowlist HTTP surface tests.

The service layer is tested in ``test_rules.py``; these tests check that the routes are
reachable only with a session, that every state change is CSRF-protected, and that
invalid input comes back as a message rather than a stack trace.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gilgamesh.config import Settings
from gilgamesh.web.app import create_app

PASSWORD = "a perfectly long passphrase"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as test_client:
        test_client.post(
            "/setup", data={"username": "admin", "password": PASSWORD}, follow_redirects=False
        )
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
