"""Shared durable EVE JSONL follower.

The follower is what lets more than one reader tail ``eve.json`` without touching the
alert tailer's position: each reader supplies its own ``position_key``. These tests
pin the semantics the alert path already relied on — start at the end on first open,
resume a persisted inode/offset, wait for a missing file, rewind a partial line,
reopen at byte zero after rotation, and save the position only after the consumer has
taken the record (at-least-once).
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from gilgamesh.db import Database
from gilgamesh.sensors import eve_tail


def _append(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


def _wait_for(seen: list[dict[str, object]], count: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while len(seen) < count and time.monotonic() < deadline:
        time.sleep(0.01)
    return len(seen) >= count


def _drain(
    follower: Iterator[dict[str, object]], seen: list[dict[str, object]], count: int
) -> None:
    for record in follower:
        seen.append(record)
        if len(seen) >= count:
            return


def _take(
    follower: Iterator[dict[str, object]],
    count: int,
    path: Path,
    text: str | None = None,
) -> list[dict[str, object]]:
    """Consume ``count`` records from ``follower``, appending ``text`` once it is tailing."""
    seen: list[dict[str, object]] = []
    thread = threading.Thread(target=_drain, args=(follower, seen, count), daemon=True)
    thread.start()
    try:
        time.sleep(0.1)  # let the follower open the file before anything is appended
        if text is not None:
            _append(path, text)
        _wait_for(seen, count)
    finally:
        thread.join(timeout=5.0)
    assert not thread.is_alive()
    return seen


def _collect(
    follower: Iterator[dict[str, object]], seen: list[dict[str, object]], stop: threading.Event
) -> None:
    for record in follower:
        seen.append(record)
        if stop.is_set():
            return


def test_follow_json_lines_yields_appended_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "eve.json"
    path.write_text("")
    monkeypatch.setattr(eve_tail, "FOLLOW_POLL_SECONDS", 0.01)
    follower = eve_tail.follow_json_lines(path, database=None, position_key="test:")
    seen = _take(follower, 1, path, '{"event_type":"flow","src_ip":"10.0.0.2"}\n')
    assert seen == [{"event_type": "flow", "src_ip": "10.0.0.2"}]


def test_follow_json_lines_skips_malformed_and_partial_lines(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "eve.json"
    path.write_text("")
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    key = f"test:{path}"
    malformed = "{not json " + "x" * 200 + "\n"
    stop = threading.Event()
    seen: list[dict[str, object]] = []
    follower = eve_tail.follow_json_lines(
        path, database=db, position_key=key, stop=stop, poll_seconds=0.01
    )
    thread = threading.Thread(target=_collect, args=(follower, seen, stop), daemon=True)
    thread.start()
    try:
        time.sleep(0.1)
        _append(path, malformed)
        _append(path, '{"event_type":"flow","src_ip":"10.0.0.9"')

        deadline = time.monotonic() + 5.0
        while db.get_setting(key) is None and time.monotonic() < deadline:
            time.sleep(0.01)
        stored = db.get_setting(key)
        assert stored is not None
        assert json.loads(stored)["offset"] == len(malformed.encode())

        time.sleep(0.1)  # a partial line is not a record
        assert seen == []

        _append(path, ',"dest_ip":"10.0.0.1"}\n')
        assert _wait_for(seen, 1)
    finally:
        stop.set()
        thread.join(timeout=5.0)
    db.close()

    assert not thread.is_alive()
    assert seen == [{"event_type": "flow", "src_ip": "10.0.0.9", "dest_ip": "10.0.0.1"}]
    assert "skipping malformed EVE record" in caplog.text
    assert "x" * 200 not in caplog.text


def test_follow_json_lines_resumes_from_persisted_position(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    path.write_text("")
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    key = f"test:{path}"
    stop = threading.Event()
    first_seen: list[dict[str, object]] = []
    first = eve_tail.follow_json_lines(
        path, database=db, position_key=key, stop=stop, poll_seconds=0.01
    )
    thread = threading.Thread(target=_collect, args=(first, first_seen, stop), daemon=True)
    thread.start()
    try:
        time.sleep(0.1)
        _append(path, '{"event_type":"flow","src_ip":"10.0.0.2"}\n')
        assert _wait_for(first_seen, 1)
    finally:
        stop.set()
        thread.join(timeout=5.0)
    assert not thread.is_alive()
    assert first_seen == [{"event_type": "flow", "src_ip": "10.0.0.2"}]
    assert db.get_setting(key) is not None

    _append(path, '{"event_type":"flow","src_ip":"10.0.0.3"}\n')
    second_seen = _take(
        eve_tail.follow_json_lines(path, database=db, position_key=key, poll_seconds=0.01),
        1,
        path,
    )
    db.close()

    assert second_seen == [{"event_type": "flow", "src_ip": "10.0.0.3"}]


def test_follow_json_lines_reopens_after_rotation(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    path.write_text("")
    stop = threading.Event()
    seen: list[dict[str, object]] = []
    follower = eve_tail.follow_json_lines(
        path, database=None, position_key="test:", stop=stop, poll_seconds=0.01
    )
    thread = threading.Thread(target=_collect, args=(follower, seen, stop), daemon=True)
    thread.start()
    try:
        time.sleep(0.1)
        _append(path, '{"event_type":"flow","src_ip":"10.0.0.2"}\n')
        assert _wait_for(seen, 1)

        rotated = tmp_path / "eve.json.1"
        rotated.write_text('{"event_type":"flow","src_ip":"10.0.0.3"}\n')
        os.replace(rotated, path)
        assert _wait_for(seen, 2)
    finally:
        stop.set()
        thread.join(timeout=5.0)

    assert not thread.is_alive()
    assert [record["src_ip"] for record in seen] == ["10.0.0.2", "10.0.0.3"]
