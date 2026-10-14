"""Authentication, sessions, CSRF, and login throttling.

**Why each choice, briefly.**

* **Argon2id** (``argon2-cffi``) for password hashing — OWASP's first recommendation, and
  memory-hard, so an offline attack on a stolen database is expensive. Parameters start at
  ``time_cost=3``, ``memory_cost=64 MiB``, ``parallelism=4`` and are re-checked on every
  login with ``check_needs_rehash``, so the cost can be raised later without invalidating
  existing passwords.
* **Opaque session ids.** The cookie carries 256 bits of randomness and nothing else; all
  state lives in the ``sessions`` row. This makes sessions **revocable** — the property a
  signed cookie cannot offer — and means both an idle and an absolute timeout apply.
* **CSRF** uses the synchronizer-token pattern: a per-session token is rendered into the
  page and checked on every unsafe method. A valid session cookie alone is not enough to
  change anything, which is the actual threat.
* **Lockout** is tracked per account and separately per client address, so one attacker
  cannot lock a household out of its own box, and one shared NAT address cannot be used to
  grind a single account forever.

The password policy accepts either a long passphrase (≥ 20 characters, which is what
people can actually remember) or a shorter one (≥ 12) that mixes at least three character
classes. Rejecting only "short and simple" pushes people towards `Passw0rd!`.
"""

from __future__ import annotations

import secrets
import time
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, InvalidHashError, VerificationError, VerifyMismatchError

from gilgamesh.db import Database


class Clock(Protocol):
    """Anything that returns the current time in seconds, so tests can control it."""

    def __call__(self) -> float: ...


#: Argon2id at the parameters from decision D-013. 64 MiB is deliberately modest: the
#: Pi has 4 GB shared with Suricata and the web app.
DEFAULT_PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)

MIN_PASSWORD_LENGTH = 12
PASSPHRASE_LENGTH = 20
MIN_CHARACTER_CLASSES = 3

DEFAULT_IDLE_TIMEOUT = timedelta(hours=1)
DEFAULT_ABSOLUTE_TIMEOUT = timedelta(hours=12)


class PasswordPolicyError(ValueError):
    """Raised when a password does not meet the policy."""


@dataclass(frozen=True, slots=True)
class User:
    """An account, as the app sees it."""

    id: int
    username: str


@dataclass(frozen=True, slots=True)
class Session:
    """An authenticated session."""

    sid: str
    user: User
    csrf_token: str


class LockoutPolicy:
    """Counts failures per key and locks the key out for a cooldown.

    Failures older than ``window`` are ignored, so a slow trickle of guesses never
    accumulates into a lockout.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window: timedelta = timedelta(minutes=15),
        lockout: timedelta = timedelta(minutes=15),
        clock: Clock = time.monotonic,
    ) -> None:
        self.max_attempts = max_attempts
        self.window = window.total_seconds()
        self.lockout_duration = lockout.total_seconds()
        self._clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}

    def record_failure(self, key: str, now: float | None = None) -> None:
        """Record one failed attempt for ``key``."""
        moment = self._now() if now is None else now
        failures = self._failures.setdefault(key, deque[float]())
        failures.append(moment)
        self._trim(key, moment)
        if len(failures) >= self.max_attempts:
            self._locked_until[key] = moment + self.lockout_duration

    def record_success(self, key: str) -> None:
        """Clear the failure history for ``key``."""
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)

    def is_locked(self, key: str, now: float | None = None) -> bool:
        """Whether ``key`` is currently locked out."""
        moment = self._now() if now is None else now
        until = self._locked_until.get(key)
        if until is None:
            return False
        if moment >= until:
            self._locked_until.pop(key, None)
            self._failures.pop(key, None)
            return False
        return True

    def advance(self, seconds: float) -> None:
        """Move the clock forward; used by tests to exercise expiry."""
        self._clock = _OffsetClock(self._now() + seconds)

    def _trim(self, key: str, moment: float) -> None:
        failures = self._failures.get(key)
        if failures is None:
            return
        while failures and moment - failures[0] > self.window:
            failures.popleft()

    def _now(self) -> float:
        clock = self._clock
        return float(clock()) if callable(clock) else 0.0


@dataclass(frozen=True, slots=True)
class _OffsetClock:
    """A monotonic clock displaced by a fixed amount, for testing expiry."""

    offset: float

    def __call__(self) -> float:
        return self.offset


def _character_classes(password: str) -> int:
    classes = 0
    if any(character.islower() for character in password):
        classes += 1
    if any(character.isupper() for character in password):
        classes += 1
    if any(character.isdigit() for character in password):
        classes += 1
    if any(not character.isalnum() for character in password):
        classes += 1
    return classes


def check_password_policy(password: str) -> None:
    """Raise :class:`PasswordPolicyError` if ``password`` is too weak."""
    if len(password) < MIN_PASSWORD_LENGTH:
        msg = f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        raise PasswordPolicyError(msg)
    if len(password) >= PASSPHRASE_LENGTH:
        return
    if _character_classes(password) < MIN_CHARACTER_CLASSES:
        msg = (
            "password must be at least "
            f"{PASSPHRASE_LENGTH} characters, or {MIN_PASSWORD_LENGTH} characters "
            "using at least three of: lower case, upper case, digits, symbols"
        )
        raise PasswordPolicyError(msg)


def hash_password(password: str, hasher: PasswordHasher | None = None) -> str:
    """Validate and hash ``password`` with Argon2id."""
    check_password_policy(password)
    return (hasher or DEFAULT_PASSWORD_HASHER).hash(password)


def verify_password(stored_hash: str, password: str, hasher: PasswordHasher | None = None) -> bool:
    """Check ``password`` against a stored Argon2id hash.

    Returns ``False`` rather than raising for a corrupt hash, because a malformed row in
    the database must not turn into a 500 on the login page.
    """
    try:
        (hasher or DEFAULT_PASSWORD_HASHER).verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, Argon2Error):
        return False
    return True


class AuthService:
    """Owns accounts, sessions, CSRF tokens, and login throttling."""

    def __init__(
        self,
        database: Database,
        *,
        hasher: PasswordHasher | None = None,
        lockout: LockoutPolicy | None = None,
        idle_timeout: timedelta = DEFAULT_IDLE_TIMEOUT,
        absolute_timeout: timedelta = DEFAULT_ABSOLUTE_TIMEOUT,
        clock: Clock = time.time,
    ) -> None:
        self._db = database
        self._hasher = hasher or DEFAULT_PASSWORD_HASHER
        self.lockout = lockout or LockoutPolicy()
        self._idle_timeout = idle_timeout.total_seconds()
        self._absolute_timeout = absolute_timeout.total_seconds()
        self._clock = clock

    def needs_setup(self) -> bool:
        """Whether the install still has no administrator account."""
        return self._db.count_users() == 0

    def create_user(self, username: str, password: str) -> User:
        """Create an account, rejecting duplicates."""
        if self._db.get_user(username) is not None:
            msg = f"user {username!r} already exists"
            raise ValueError(msg)
        password_hash = hash_password(password, self._hasher)
        user_id = self._db.create_user(username, password_hash, self._now())
        return User(id=user_id, username=username)

    def login(self, username: str, password: str, client: str | None = None) -> Session | None:
        """Authenticate and start a session, or return ``None`` on failure."""
        account_key = f"user:{username}"
        client_key = f"client:{client}" if client else None
        for key in (account_key, client_key):
            if key and self.lockout.is_locked(key):
                return None

        record = self._db.get_user(username)
        if record is None:
            # Hash anyway so a missing account and a wrong password take similar time.
            verify_password(self._hasher.hash("not-a-real-password"), password, self._hasher)
            self._fail(account_key, client_key)
            return None

        user_id, stored_hash = record
        if not verify_password(stored_hash, password, self._hasher):
            self._fail(account_key, client_key)
            return None

        self.lockout.record_success(account_key)
        if client_key:
            self.lockout.record_success(client_key)
        self._db.record_login_attempt(account_key, self._now(), True)
        return self.start_session(User(id=user_id, username=username))

    def start_session(self, user: User) -> Session:
        """Create a session with a fresh CSRF token."""
        now = self._now()
        session = Session(
            sid=secrets.token_urlsafe(32),
            user=user,
            csrf_token=secrets.token_urlsafe(32),
        )
        self._db.insert_session(
            session.sid,
            user.id,
            session.csrf_token,
            created_ts=now,
        )
        return session

    def validate_session(self, sid: str) -> Session | None:
        """Return a live session, or ``None`` if unknown, idle, or expired."""
        record = self._db.get_session(sid)
        if record is None:
            return None
        user_id, csrf_token, created_ts, last_seen_ts = record
        now = self._now()
        # Two independent limits: idle slides on activity, absolute does not.
        if now - created_ts > self._absolute_timeout or now - last_seen_ts > self._idle_timeout:
            self._db.delete_session(sid)
            return None

        username = self._db.get_username(user_id)
        if username is None:
            return None
        self._db.touch_session(sid, now)
        return Session(sid=sid, user=User(id=user_id, username=username), csrf_token=csrf_token)

    def revoke_session(self, sid: str) -> None:
        """Destroy a session."""
        self._db.delete_session(sid)

    def change_password(self, username: str, current_password: str, new_password: str) -> User:
        """Change a user's password after re-checking the current one.

        Every existing session for the user is revoked, because a password change is
        exactly the moment an owner expects "log everyone else out" — including a
        refresh of this browser's own session, which the caller re-issues.
        """
        record = self._db.get_user(username)
        if record is None or not verify_password(record[1], current_password):
            msg = "current password is incorrect"
            raise PasswordPolicyError(msg)
        check_password_policy(new_password)
        self._db.set_password(username, hash_password(new_password))
        self._db.delete_sessions_for_user(record[0])
        return User(id=record[0], username=username)

    def expire_session(self, sid: str) -> None:
        """Age a session past both timeouts so it is dead.

        Used by tests to exercise expiry without sleeping. Backdates by the timeouts
        actually in force on this service, plus a second of slack so the comparison is
        unambiguous.
        """
        now = self._now()
        self._db.backdate_session(
            sid,
            last_seen_ts=now - self._idle_timeout - 1.0,
            created_ts=now - self._absolute_timeout - 1.0,
        )

    def backdate_created(self, sid: str, seconds: float) -> None:
        """Age a session's creation time only, leaving it "active".

        This is how the absolute timeout is tested separately from the idle one: a
        session that keeps being used must still die once it reaches its absolute age.
        """
        record = self._db.get_session(sid)
        if record is None:
            return
        last_seen_ts = record[3]
        self._db.backdate_session(sid, last_seen_ts=last_seen_ts, created_ts=self._now() - seconds)

    def check_csrf(self, session: Session | None, supplied: str | None) -> bool:
        """Validate a CSRF token in constant time."""
        if session is None or not supplied:
            return False
        return secrets.compare_digest(session.csrf_token, supplied)

    def _fail(self, account_key: str, client_key: str | None) -> None:
        now = self._now()
        self.lockout.record_failure(account_key, now)
        self._db.record_login_attempt(account_key, now, False)
        if client_key:
            self.lockout.record_failure(client_key, now)

    def _now(self) -> float:
        clock = self._clock
        return float(clock()) if callable(clock) else 0.0


def create_auth_service(database: Database) -> AuthService:
    """Build an :class:`AuthService` with the shipped defaults."""
    return AuthService(database)
