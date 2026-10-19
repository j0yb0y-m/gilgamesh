"""M12 — authentication, sessions, CSRF, and first-run wizard tests.

Gilgamesh's web UI is the only way to configure a security tool, so these tests lean
towards the attacker's side of the table: they check that sessions are revocable, that
CSRF is rejected, that brute force is throttled, and that a fresh install cannot be
claimed by somebody who is merely on the LAN.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.web.app import create_app
from gilgamesh.web.auth import (
    DEFAULT_PASSWORD_HASHER,
    AuthService,
    LockoutPolicy,
    PasswordPolicyError,
    create_auth_service,
    hash_password,
    verify_password,
)


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "gilgamesh.db")
    database.initialize()
    yield database
    database.close()


@pytest.fixture
def auth(db: Database) -> AuthService:
    return create_auth_service(db)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    """A TestClient with the application's lifespan actually running.

    Entering the context manager is what triggers the ``lifespan`` handler, so a client
    built without it would have no database and no auth service.
    """
    with TestClient(create_app(Settings(data_dir=tmp_path))) as test_client:
        yield test_client


def setup_payload(client: TestClient, username: str, password: str) -> dict[str, str]:
    """The wizard's form fields, including the token the console owner would read.

    ``ensure_setup_token`` returns the same value the web process logs at start-up;
    reading it here is what a human does from ``journalctl`` before typing it in.
    """
    token = cast(FastAPI, client.app).state.auth.ensure_setup_token()
    return {"username": username, "password": password, "setup_token": token or ""}


def csrf_from(client: TestClient, path: str = "/") -> str:
    """Read the session's CSRF token out of a rendered page."""
    body = client.get(path).text
    marker = 'name="csrf_token" value="'
    start = body.index(marker) + len(marker)
    return body[start : body.index('"', start)]


# --- password hashing ---------------------------------------------------------


def test_password_hash_is_argon2id_and_salted() -> None:
    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")

    assert first.startswith("$argon2id$")
    assert first != second  # salted


def test_password_verifies_against_its_own_hash() -> None:
    stored = hash_password("s3cret-passphrase")

    assert verify_password(stored, "s3cret-passphrase") is True
    assert verify_password(stored, "wrong-passphrase") is False


def test_verify_survives_a_corrupt_hash() -> None:
    assert verify_password("not-a-hash", "anything") is False


def test_stored_hash_is_never_the_plaintext() -> None:
    assert "correct horse" not in hash_password("correct horse battery staple")


def test_hasher_uses_documented_parameters() -> None:
    hasher = DEFAULT_PASSWORD_HASHER

    assert hasher.time_cost >= 3
    assert hasher.memory_cost >= 65536
    assert hasher.parallelism >= 2


# --- password policy ----------------------------------------------------------


@pytest.mark.parametrize("password", ["short", "alllowercase123", "12345678901234"])
def test_weak_passwords_are_rejected(password: str) -> None:
    with pytest.raises(PasswordPolicyError):
        hash_password(password)


def test_long_passphrase_is_accepted() -> None:
    assert hash_password("a perfectly long and memorable passphrase").startswith("$argon2id$")


# --- users and setup ----------------------------------------------------------


def test_fresh_install_needs_setup(db: Database, auth: AuthService) -> None:
    assert auth.needs_setup() is True

    auth.create_user("admin", "a perfectly long passphrase")

    assert auth.needs_setup() is False


def test_duplicate_usernames_are_refused(db: Database, auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")

    with pytest.raises(ValueError, match="already exists"):
        auth.create_user("admin", "another perfectly long passphrase")


def test_login_succeeds_with_the_right_password(auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")

    session = auth.login("admin", "a perfectly long passphrase")

    assert session is not None
    assert session.user.username == "admin"


def test_login_fails_with_the_wrong_password(auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")

    assert auth.login("admin", "wrong passphrase") is None


def test_login_with_unknown_user_fails(auth: AuthService) -> None:
    assert auth.login("nobody", "a perfectly long passphrase") is None


# --- sessions -----------------------------------------------------------------


def test_session_validates_and_can_be_revoked(auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")
    session = auth.login("admin", "a perfectly long passphrase")
    assert session is not None

    assert auth.validate_session(session.sid) is not None
    auth.revoke_session(session.sid)
    assert auth.validate_session(session.sid) is None


def test_unknown_session_id_is_rejected(auth: AuthService) -> None:
    assert auth.validate_session("made-up-token") is None


def test_expired_session_is_rejected(auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")
    session = auth.login("admin", "a perfectly long passphrase")
    assert session is not None

    auth.expire_session(session.sid)

    assert auth.validate_session(session.sid) is None


def test_absolute_timeout_beats_activity(auth: AuthService) -> None:
    """A session that never goes idle must still die at the absolute limit."""
    auth.create_user("admin", "a perfectly long passphrase")
    session = auth.login("admin", "a perfectly long passphrase")
    assert session is not None

    # Still well inside the 1 hour idle timeout, but past the 12 hour absolute one.
    auth.backdate_created(session.sid, seconds=13 * 3600)

    assert auth.validate_session(session.sid) is None


def test_each_session_token_is_unique(auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")

    tokens = {
        auth.login("admin", "a perfectly long passphrase").sid  # type: ignore[union-attr]
        for _ in range(5)
    }

    assert len(tokens) == 5


# --- CSRF ---------------------------------------------------------------------


def test_csrf_token_is_bound_to_the_session(auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")
    session = auth.login("admin", "a perfectly long passphrase")
    assert session is not None

    other = auth.login("admin", "a perfectly long passphrase")
    assert other is not None

    assert session.csrf_token != other.csrf_token


def test_csrf_token_is_sufficiently_long(auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")
    session = auth.login("admin", "a perfectly long passphrase")
    assert session is not None

    assert len(session.csrf_token) >= 32


# --- lockout ------------------------------------------------------------------


def test_repeated_failures_lock_the_account() -> None:
    policy = LockoutPolicy(
        max_attempts=3, window=timedelta(minutes=15), lockout=timedelta(minutes=15)
    )

    for _ in range(2):
        policy.record_failure("admin")
    assert policy.is_locked("admin") is False

    policy.record_failure("admin")

    assert policy.is_locked("admin") is True


def test_a_successful_login_clears_the_counter(auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")
    policy = auth.lockout
    policy.record_failure("admin")
    policy.record_failure("admin")

    auth.login("admin", "a perfectly long passphrase")

    assert policy.is_locked("admin") is False


def test_lockout_expires() -> None:
    policy = LockoutPolicy(
        max_attempts=2, window=timedelta(minutes=15), lockout=timedelta(minutes=1)
    )
    policy.record_failure("key")
    policy.record_failure("key")
    assert policy.is_locked("key") is True

    policy.advance(120.0)

    assert policy.is_locked("key") is False


def test_lockout_is_per_key() -> None:
    policy = LockoutPolicy(
        max_attempts=2, window=timedelta(minutes=15), lockout=timedelta(minutes=15)
    )
    policy.record_failure("admin")
    policy.record_failure("admin")

    assert policy.is_locked("admin") is True
    assert policy.is_locked("someone-else") is False


def test_login_is_refused_while_locked_out(auth: AuthService) -> None:
    auth.create_user("admin", "a perfectly long passphrase")
    for _ in range(6):
        auth.login("admin", "wrong passphrase")

    assert auth.login("admin", "a perfectly long passphrase") is None


def test_lockout_survives_a_restart(db: Database) -> None:
    """A restarted service must not hand an attacker a fresh set of guesses.

    The in-memory counters die with the process; the persisted attempts are what keeps
    the throttle in force across ``systemctl restart``.
    """
    first = create_auth_service(db)
    first.create_user("admin", "a perfectly long passphrase")
    for _ in range(6):
        first.login("admin", "wrong passphrase")

    second = create_auth_service(db)

    assert second.login("admin", "a perfectly long passphrase") is None


def test_an_attacker_cannot_lock_the_owner_out_from_a_different_address(
    db: Database,
) -> None:
    """The property that matters on a home LAN: guests can't lock the owner out."""
    auth = create_auth_service(db)
    auth.create_user("admin", "a perfectly long passphrase")
    for _ in range(6):
        auth.login("admin", "wrong passphrase", client="10.0.0.66")

    # The owner, from their own address, can still sign in…
    assert auth.login("admin", "a perfectly long passphrase", client="10.0.0.5") is not None
    # …while the attacker's address stays throttled.
    assert auth.login("admin", "a perfectly long passphrase", client="10.0.0.66") is None


# --- HTTP surface -------------------------------------------------------------


def test_fresh_install_redirects_to_setup(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)

    assert response.status_code in (302, 303, 307)
    assert "/setup" in response.headers["location"]


def test_setup_page_is_reachable_before_any_user_exists(client: TestClient) -> None:
    response = client.get("/setup")

    assert response.status_code == 200
    assert "password" in response.text.lower()


def test_wizard_creates_the_admin_and_logs_in(client: TestClient) -> None:
    response = client.post(
        "/setup",
        data=setup_payload(client, "admin", "a perfectly long passphrase"),
        follow_redirects=False,
    )

    assert response.status_code in (302, 303, 307)
    assert client.cookies.get("gilgamesh_session")


def test_setup_refuses_the_wrong_token(client: TestClient) -> None:
    """The wizard must not be claimable by someone who only found the open port."""
    payload = setup_payload(client, "admin", "a perfectly long passphrase")
    payload["setup_token"] = "not-the-token"

    response = client.post("/setup", data=payload, follow_redirects=False)

    assert response.status_code == 400
    assert not client.cookies.get("gilgamesh_session")


def test_setup_refuses_a_missing_token(client: TestClient) -> None:
    response = client.post(
        "/setup",
        data={"username": "admin", "password": "a perfectly long passphrase"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert not client.cookies.get("gilgamesh_session")


def test_wizard_is_closed_once_a_user_exists(client: TestClient) -> None:
    client.post("/setup", data=setup_payload(client, "admin", "a perfectly long passphrase"))

    response = client.get("/setup", follow_redirects=False)

    assert response.status_code in (302, 303, 307)
    assert response.headers["location"] == "/"


def test_setup_rejects_a_weak_password(client: TestClient) -> None:
    payload = setup_payload(client, "admin", "short")
    response = client.post("/setup", data=payload)

    assert response.status_code in (200, 400, 422)
    assert not client.cookies.get("gilgamesh_session")


def test_protected_page_requires_a_session(client: TestClient) -> None:
    client.post("/setup", data=setup_payload(client, "admin", "a perfectly long passphrase"))
    client.cookies.clear()

    response = client.get("/", follow_redirects=False)

    assert response.status_code in (302, 303, 307)
    assert "/login" in response.headers["location"]


def test_login_page_is_reachable(client: TestClient) -> None:
    assert client.get("/login").status_code == 200


def test_login_rejects_bad_credentials(client: TestClient) -> None:
    client.post("/setup", data=setup_payload(client, "admin", "a perfectly long passphrase"))
    client.cookies.clear()

    response = client.post(
        "/login", data={"username": "admin", "password": "wrong"}, follow_redirects=False
    )

    assert response.status_code == 401
    assert not client.cookies.get("gilgamesh_session")


def test_login_succeeds_and_sets_a_cookie(client: TestClient) -> None:
    client.post("/setup", data=setup_payload(client, "admin", "a perfectly long passphrase"))
    client.cookies.clear()

    client.post("/login", data={"username": "admin", "password": "a perfectly long passphrase"})

    assert client.cookies.get("gilgamesh_session")


def test_logout_clears_the_session(client: TestClient) -> None:
    client.post("/setup", data=setup_payload(client, "admin", "a perfectly long passphrase"))
    response = client.post(
        "/logout", data={"csrf_token": csrf_from(client)}, follow_redirects=False
    )

    assert response.status_code in (302, 303, 307)
    assert not client.cookies.get("gilgamesh_session")


def test_logout_without_csrf_is_rejected(client: TestClient) -> None:
    """Signing the owner out is a state change and needs the same token as the rest."""
    client.post("/setup", data=setup_payload(client, "admin", "a perfectly long passphrase"))

    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 403
    assert client.cookies.get("gilgamesh_session")


def test_mutating_request_without_csrf_is_rejected(client: TestClient) -> None:
    """The core CSRF property: a valid session cookie is still not enough."""
    client.post("/setup", data=setup_payload(client, "admin", "a perfectly long passphrase"))

    response = client.post("/settings", data={"retention_days": "1"})

    assert response.status_code == 403


def test_session_cookie_is_httponly(client: TestClient) -> None:
    """The cookie that actually authenticates the owner must be HttpOnly and Lax."""
    response = client.post(
        "/setup",
        data=setup_payload(client, "admin", "a perfectly long passphrase"),
        follow_redirects=False,
    )

    set_cookie = response.headers["set-cookie"]

    assert "gilgamesh_session" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie.replace("Lax", "lax")


def test_healthz_stays_public(client: TestClient) -> None:
    assert client.get("/api/healthz").status_code == 200


def test_setup_completes_within_reasonable_time(client: TestClient) -> None:
    """Argon2id at production parameters must not make the wizard feel broken."""
    started = datetime.now(UTC)
    client.post("/setup", data=setup_payload(client, "admin", "a perfectly long passphrase"))

    assert (datetime.now(UTC) - started).total_seconds() < 5.0
