"""End-to-end fixtures: run the real server and reach it with a real browser.

These tests spawn ``gilgamesh-web`` exactly the way the systemd unit does — a
separate process on a real port with its own data directory — and drive it with
the system Chrome (``--browser-channel chrome``). Everything stays local: the
server binds ``127.0.0.1`` with a throwaway data directory, and the browser is
pointed only at itself. No attack traffic is generated and no real device is
touched (see the safety rules in ``AGENTS.md``).

Run with::

    uv run pytest tests/e2e -m e2e --browser-channel chrome

Add ``--headed`` to watch the browser, or ``--screenshot only-on-failure`` to
keep evidence in ``test-results/``.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

_SERVER_START_TIMEOUT = 20.0
_SERVER_STOP_TIMEOUT = 10.0


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_ready(url: str, log_path: Path) -> None:
    """Poll the liveness endpoint until the real process answers."""
    deadline = time.monotonic() + _SERVER_START_TIMEOUT
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    tail = log_path.read_text(errors="replace")[-2000:] if log_path.exists() else "<no log>"
    raise RuntimeError(f"server at {url} did not become ready. server log tail:\n{tail}")


@pytest.fixture(scope="session")
def server_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Path for the real server's log, shared by the fixtures below."""
    return tmp_path_factory.mktemp("gilgamesh-e2e") / "server.log"


@dataclass(frozen=True, slots=True)
class RunningServer:
    """The real ``gilgamesh-web`` process, for the tests and the teardown."""

    url: str
    process: subprocess.Popen[bytes]
    log_path: Path


@pytest.fixture(scope="session")
def server(server_log: Path) -> Iterator[RunningServer]:
    """Start one real ``gilgamesh-web`` process for the whole session.

    A session-scoped process keeps the suite fast, which also means the tests
    intentionally share one fresh database: the wizard test runs first and
    creates the admin the later tests sign in with. Run the file whole.

    A test may stop this process deliberately — the graceful-shutdown test does, and it
    must therefore run last. The teardown below is written to survive that.
    """
    script = Path(sys.prefix) / "bin" / "gilgamesh-web"
    if not script.exists():  # pragma: no cover - only on a broken checkout
        raise RuntimeError("console script gilgamesh-web is missing; run `uv sync` first")

    port = _free_port()
    data_dir = server_log.parent
    env = os.environ | {
        "GILGAMESH_DATA_DIR": str(data_dir),
        "GILGAMESH_HOST": "127.0.0.1",
        "GILGAMESH_PORT": str(port),
    }
    log_path = server_log
    with log_path.open("w") as log:
        process = subprocess.Popen(
            [str(script)],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            _wait_ready(f"http://127.0.0.1:{port}/api/healthz", log_path)
            yield RunningServer(url=f"http://127.0.0.1:{port}", process=process, log_path=log_path)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=_SERVER_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:  # pragma: no cover - a real hang
                    process.kill()
                    process.wait(timeout=_SERVER_STOP_TIMEOUT)


@pytest.fixture(scope="session")
def app_url(server: RunningServer) -> str:
    return server.url


def read_setup_token(log_path: Path, deadline: float = _SERVER_START_TIMEOUT) -> str:
    """The first-run setup token, scraped from the server log as the owner would.

    The web process logs it once at start-up (that *is* the intended delivery to the
    owner — a journal line only the console can see), so this is exactly the value a
    human would copy out of ``journalctl`` before the wizard accepts them.
    """
    pattern = re.compile(r"setup token '([A-Za-z0-9_-]+)'")
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            found = pattern.search(log_path.read_text(errors="replace"))
        except OSError:  # pragma: no cover - log being rotated mid-read
            found = None
        if found:
            return found.group(1)
        time.sleep(0.1)
    tail = log_path.read_text(errors="replace")[-2000:] if log_path.exists() else "<no log>"
    raise RuntimeError(f"no setup token in the server log. log tail:\n{tail}")


@pytest.fixture(scope="session")
def setup_token(server_log: Path) -> str:
    """The wizard's token, as read from the running server's log."""
    return read_setup_token(server_log)
