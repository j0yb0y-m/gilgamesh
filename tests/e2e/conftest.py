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
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
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
def app_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Start one real ``gilgamesh-web`` process for the whole session.

    A session-scoped process keeps the suite fast, which also means the tests
    intentionally share one fresh database: the wizard test runs first and
    creates the admin the later tests sign in with. Run the file whole.
    """
    script = Path(sys.prefix) / "bin" / "gilgamesh-web"
    if not script.exists():  # pragma: no cover - only on a broken checkout
        raise RuntimeError("console script gilgamesh-web is missing; run `uv sync` first")

    port = _free_port()
    data_dir = tmp_path_factory.mktemp("gilgamesh-e2e")
    env = os.environ | {
        "GILGAMESH_DATA_DIR": str(data_dir),
        "GILGAMESH_HOST": "127.0.0.1",
        "GILGAMESH_PORT": str(port),
    }
    log_path = data_dir / "server.log"
    with log_path.open("w") as log:
        process = subprocess.Popen(
            [str(script)],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            _wait_ready(f"http://127.0.0.1:{port}/api/healthz", log_path)
            yield f"http://127.0.0.1:{port}"
        finally:
            process.terminate()
            try:
                process.wait(timeout=_SERVER_STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=_SERVER_STOP_TIMEOUT)
