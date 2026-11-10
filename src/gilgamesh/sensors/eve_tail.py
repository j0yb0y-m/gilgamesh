"""Durable follower for Suricata EVE JSONL files.

Suricata appends one JSON object per line to ``eve.json``. Several Gilgamesh readers
need the same stream — the alert tailer turns ``alert`` records into events, and the
behaviour service reads ``flow`` and ``dns`` records — but each reader must keep its
own position, or one reader's progress would silently skip records for the other.

This module owns only the *transport*: open the file, wait for it to appear, read
whole lines, parse JSON, survive rotation, and persist an inode/byte-offset position
under a caller-supplied key. It does not interpret records.

**At-least-once.** The position is saved only after the consumer has taken a record,
so a crash between delivery and persistence replays that one record rather than losing
it. Malformed JSON has no consumer to wait for: it is logged (truncated) and skipped,
and the position still advances so a bad line cannot wedge the tailer.

**History is not news.** On the first open the follower starts at the end of the file.
A persisted position is resumed only when it still refers to the same inode and is
inside the file. A missing file is waited for, because at boot the sensor normally
starts before Suricata has created its log.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import IO, Protocol, cast

from gilgamesh.db import Database

logger = logging.getLogger(__name__)

#: How long the follower waits before retrying an exhausted read. Half a second keeps
#: alert latency low without spinning a core on the Pi.
FOLLOW_POLL_SECONDS = 0.5

#: How much of a malformed record is safe to log. A bad line can be arbitrarily long,
#: and the log is written to disk on a Pi.
_MALFORMED_PREVIEW_CHARS = 120


class StopSignal(Protocol):
    """The part of :class:`threading.Event` the follower needs."""

    def is_set(self) -> bool: ...


def follow_json_lines(
    path: Path,
    *,
    database: Database | None,
    position_key: str,
    stop: StopSignal | None = None,
    poll_seconds: float | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[dict[str, object]]:
    """Yield each complete JSON object appended to ``path``.

    ``position_key`` is the full ``app_settings`` key this reader owns; callers prefix
    it so the alert tailer and the behaviour service never share a position.

    ``poll_seconds`` defaults to :data:`FOLLOW_POLL_SECONDS`, resolved when iteration
    starts rather than when the function is defined, so tests (and the service) can
    shorten the poll interval.

    ``sleep`` is injectable for the same reason: the loop is otherwise driven by real
    wall-clock waits. ``stop`` is any object with an ``is_set()`` method; passing
    ``None`` follows forever.
    """
    delay = FOLLOW_POLL_SECONDS if poll_seconds is None else poll_seconds
    handle: IO[str] | None = None
    inode = -1
    offset = 0
    first_open = True
    waited_for_file = False
    try:
        while True:
            if stop is not None and stop.is_set():
                return
            if handle is None:
                try:
                    if first_open and not waited_for_file:
                        handle, inode, offset = _open_initial(path, database, position_key)
                        first_open = False
                    else:
                        # A file that appeared after the follower started, or a
                        # rotated file, contains new data: read it from byte zero.
                        handle, inode = _open_from_start(path)
                        first_open = False
                        offset = 0
                        _save_position(database, position_key, inode, offset)
                except OSError:
                    waited_for_file = True
                    sleep(delay)
                    continue

            line = handle.readline()
            if not line:
                sleep(delay)
                try:
                    current = path.stat()
                except OSError:
                    continue
                if current.st_ino != inode:
                    handle.close()
                    handle = None
                continue
            if not line.endswith("\n"):
                # A record still being written. Rewind and read it again whole.
                handle.seek(offset)
                sleep(delay)
                continue

            offset = handle.tell()
            record = _parse_json(line)
            if record is not None:
                yield record
            # Persist only after the consumer has taken the record: a crash between
            # the two replays it (at-least-once), never loses it. Malformed lines
            # have no consumer, so their bytes are persisted immediately.
            _save_position(database, position_key, inode, offset)
    finally:
        if handle is not None:
            handle.close()


def _parse_json(line: str) -> dict[str, object] | None:
    """Parse one complete EVE line, or return ``None`` for anything unusable."""
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        logger.warning("skipping malformed EVE record: %s", line.strip()[:_MALFORMED_PREVIEW_CHARS])
        return None
    if not isinstance(parsed, dict):
        return None
    return cast("dict[str, object]", parsed)


def _open_initial(
    path: Path, database: Database | None, position_key: str
) -> tuple[IO[str], int, int]:
    """Open for the first time, resuming a persisted position or seeking to the end."""
    stored = _load_position(database, position_key)
    if stored is None:
        return _open_at_end(path)
    inode, offset = stored
    try:
        size = path.stat().st_size
        if path.stat().st_ino == inode and 0 <= offset <= size:
            handle = path.open(encoding="utf-8", errors="replace")
            handle.seek(offset)
            return handle, inode, offset
    except OSError:
        pass
    return _open_at_end(path)


def _load_position(database: Database | None, position_key: str) -> tuple[int, int] | None:
    if database is None:
        return None
    raw = database.get_setting(position_key)
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
        return int(parsed["inode"]), int(parsed["offset"])
    except (ValueError, TypeError, KeyError):
        return None


def _save_position(database: Database | None, position_key: str, inode: int, offset: int) -> None:
    if database is None:
        return
    try:
        database.set_setting(
            position_key,
            json.dumps({"inode": inode, "offset": offset}, separators=(",", ":")),
        )
    except Exception:
        # A counter that cannot be persisted is not a reason to stop ingesting.
        logger.exception("could not persist the EVE log position")


def _open_at_end(path: Path) -> tuple[IO[str], int, int]:
    """Open an existing file for following from its current end."""
    handle = path.open(encoding="utf-8", errors="replace")
    size = path.stat().st_size
    handle.seek(size)
    return handle, path.stat().st_ino, size


def _open_from_start(path: Path) -> tuple[IO[str], int]:
    """Open a newly-created (rotated) file at byte zero."""
    handle = path.open(encoding="utf-8", errors="replace")
    return handle, path.stat().st_ino
