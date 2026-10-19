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
* **Lockout** is enforced on the client address (falling back to the account name only
  for callers that have no address), so one attacker cannot lock a household out of its
  own box just by guessing the owner's password a few times.

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

#: A pre-computed hash verified when no real one exists (unknown user) or the account is
#: locked. Verifying against a constant costs exactly one hash check, so an unknown
#: account is indistinguishable from a wrong password by timing — hashing a fresh dummy
#: each time (the previous behaviour) made the unknown case *twice* as slow instead.
_DUMMY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$6sTFYL1yyCBOKzjw3s/yEw"
    "$66YeeX7N0ry5U9Pqlnn67ms5DmyRf+rxETDYan7H6FI"
)

MIN_PASSWORD_LENGTH = 12
PASSPHRASE_LENGTH = 20
MIN_CHARACTER_CLASSES = 3

#: ``app_settings`` key holding the first-run setup token. The name is a settings key,
#: not a credential; the token itself is random per install.
SETUP_TOKEN_KEY = "setup_token"  # noqa: S105
#: The longest accepted account name. The login form and the users table are text.
USERNAME_MAX_LENGTH = 64

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

    def ensure_setup_token(self) -> str | None:
        """The first-run setup token, generated on first use.

        The wizard is reachable by anyone who can open the port before the owner has
        claimed the box, which on a home LAN is exactly the *wrong* someone. The token
        closes that window: it is printed to the journal by the web process at start-up
        and must be typed into the wizard, so possession of the console — not merely
        network adjacency — is what claims the install. Returns ``None`` once an
        administrator exists.
        """
        if not self.needs_setup():
            return None
        existing = self._db.get_setting(SETUP_TOKEN_KEY)
        if existing:
            return existing
        token = secrets.token_urlsafe(16)
        self._db.set_setting(SETUP_TOKEN_KEY, token)
        return token

    def verify_setup_token(self, supplied: str | None) -> bool:
        """Constant-time check of a submitted setup token."""
        expected = self._db.get_setting(SETUP_TOKEN_KEY)
        if expected is None or not supplied:
            return False
        return secrets.compare_digest(expected, supplied)

    def clear_setup_token(self) -> None:
        """Forget the setup token once the administrator has been created."""
        self._db.execute("DELETE FROM app_settings WHERE key = ?", (SETUP_TOKEN_KEY,))

    def create_user(self, username: str, password: str) -> User:
        """Create the administrator account, rejecting duplicates and bad names."""
        name = username.strip()
        if not 1 <= len(name) <= USERNAME_MAX_LENGTH or not name.isprintable():
            msg = f"username must be 1-{USERNAME_MAX_LENGTH} printable characters"
            raise ValueError(msg)
        # The product has exactly one account (v1). Enforcing it here rather than only
        # in the wizard's "does anyone exist" check keeps a racing second POST from
        # creating a second administrator behind the owner's back.
        if self._db.count_users() > 0:
            msg = "an administrator account already exists"
            raise ValueError(msg)
        if self._db.get_user(name) is not None:
            msg = f"user {name!r} already exists"
            raise ValueError(msg)
        password_hash = hash_password(password, self._hasher)
        user_id = self._db.create_user(name, password_hash, self._now())
        return User(id=user_id, username=name)

    def login(self, username: str, password: str, client: str | None = None) -> Session | None:
        """Authenticate and start a session, or return ``None`` on failure.

        Lockout is enforced on the client address when one is known — the property that
        matters on a home LAN, where a misbehaving guest must not be able to lock the
        owner out of their own box — and on the account only for callers that have no
        address (a local check).
        """
        account_key = f"user:{username}"
        client_key = f"client:{client}" if client else None
        lock_key = client_key or account_key
        if self._is_locked(lock_key):
            # Burn the same hash time as a real check before answering, so an attacker
            # cannot tell a locked account from a wrong password by stopwatch.
            verify_password(_DUMMY_HASH, password, self._hasher)
            return None

        record = self._db.get_user(username)
        if record is None:
            # Same single hash check as the wrong-password path: similar time, and no
            # second 64 MiB Argon2 pass per guess.
            verify_password(_DUMMY_HASH, password, self._hasher)
            self._fail(lock_key)
            return None

        user_id, stored_hash = record
        if not verify_password(stored_hash, password, self._hasher):
            self._fail(lock_key)
            return None

        self.lockout.record_success(account_key)
        if client_key:
            self.lockout.record_success(client_key)
        self._db.record_login_attempt(lock_key, self._now(), True)
        return self.start_session(User(id=user_id, username=username))

    def _is_locked(self, lock_key: str) -> bool:
        """Whether ``lock_key`` is throttled, in memory or on disk.

        The in-memory counters die with the process, so without the persisted attempts a
        ``systemctl restart`` (which any local fault can trigger) would hand an attacker
        a full set of fresh guesses. Both are consulted; either one can lock.
        """
        if self.lockout.is_locked(lock_key):
            return True
        since = self._now() - self.lockout.window
        return self._db.failed_attempts_since(lock_key, since) >= self.lockout.max_attempts

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

    def _fail(self, lock_key: str) -> None:
        now = self._now()
        self.lockout.record_failure(lock_key, now)
        # Record under the same key the lockout uses, so the persisted count can back it.
        self._db.record_login_attempt(lock_key, now, False)

    def _now(self) -> float:
        clock = self._clock
        return float(clock()) if callable(clock) else 0.0


def create_auth_service(database: Database) -> AuthService:
    """Build an :class:`AuthService` with the shipped defaults."""
    return AuthService(database)
