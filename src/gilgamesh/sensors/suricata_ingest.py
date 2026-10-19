"""Suricata EVE JSON ingestion and rule management (catalogue item #6).

**Why ingestion.** Suricata runs as a **separate process** from Gilgamesh — which is
also why its GPLv2 licence never links into ours (decision D-002) — and communicates by
appending JSON to ``eve.json``. This module is the tailer that turns those lines into the
same normalized :class:`~gilgamesh.models.Event` every other detector emits, so the
pipeline, storage, UI, and notifiers cannot tell a signature alert from an ARP alert.

**Verified field names** (Suricata 8 documentation,
``docs.suricata.io/en/latest/output/eve/eve-json-format.html``, retrieved 2026-10-14):
the common section carries ``timestamp``, ``flow_id``, ``event_type``, ``src_ip``,
``src_port``, ``dest_ip``, ``dest_port``, ``proto``, ``in_iface``, ``app_proto``; the
``alert`` object carries ``action``, ``gid``, ``signature_id``, ``rev``, ``signature``,
``category`` and ``severity``. Note Suricata spells the destination **``dest_ip``**, not
``dst_ip`` — getting that wrong silently loses the peer of every alert.

**UNVERIFIED — severity direction.** The docs show ``severity: 1`` on a malware
command-and-control signature and ``severity: 2`` on "generic suspicious POST", which is
consistent with Suricata's convention that **1 is the highest** severity and 4 the lowest.
The documentation page does not state this explicitly, so the mapping lives in a
constructor argument (:class:`EveIngestor`) rather than being hard-coded, and can be
inverted in one place if it is ever shown wrong. Tracked in
``docs/research/09-open-questions.md``.

**Only ``alert`` records are treated as events.** Suricata also emits ``dns``, ``dhcp``,
``arp``, ``flow``, ``http`` and many other record types. Those are *facts*, not verdicts,
and Gilgamesh's own detectors draw their conclusions from raw traffic — so they are
ignored here rather than turned into duplicate, lower-quality alerts.

**Rule management.** Enabling and disabling individual signatures is done through
``suricata-update``'s filter files, ``/etc/suricata/disable.conf`` and
``/etc/suricata/enable.conf``. Two facts drive the implementation, both verified from
the tool's own sources (2026-10-14):

* ``suricata-update`` has **no** ``disable-rule``/``enable-rule`` command — only
  source-level ones (``add-source``, ``enable-source``, ``disable-source``,
  ``remove-source``, ``list-sources``, ``update-sources``). Filtering individual rules
  is done by those files.
* The ``load_filters`` parser in ``suricata-update/main.py`` **skips any line starting
  with ``#``**. The shipped sample files are therefore commented out in full, which is
  why they contain only inactive examples. Gilgamesh consequently writes directives
  **without** a ``#`` prefix, one ``gid:signature_id`` per line.

Because only integers are ever rendered, no rule text can reach those files — that is
the rule-injection guard from decision D-017, enforced by validation rather than by
escaping.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Protocol, cast

from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.pipeline import Pipeline, PipelineDecision

logger = logging.getLogger(__name__)

#: How long the tailer waits before retrying an exhausted read. Half a second keeps
#: alert latency low without spinning a core on the Pi.
FOLLOW_POLL_SECONDS = 0.5


class StopSignal(Protocol):
    """The part of :class:`threading.Event` the tailer needs."""

    def is_set(self) -> bool: ...


#: Suricata's 1-4 alert severity mapped onto Gilgamesh's scale. See the module
#: docstring: the "1 is highest" direction is inferred from the documentation examples
#: rather than stated outright, so it is overridable rather than hard-coded.
DEFAULT_SEVERITY_MAP: dict[int, Severity] = {
    1: Severity.CRITICAL,
    2: Severity.HIGH,
    3: Severity.MEDIUM,
    4: Severity.LOW,
}

_DEFAULT_RULE_GID = 1
_UINT32_MAX = 2**32 - 1


@dataclass(frozen=True, slots=True)
class RuleSetting:
    """One rule's enable/disable state as configured in the Gilgamesh UI."""

    signature_id: int
    enabled: bool
    gid: int = _DEFAULT_RULE_GID

    def __post_init__(self) -> None:
        # Validation, not escaping: only an integer can ever be rendered, so there is
        # no path by which rule text reaches disable.conf (decision D-017). The
        # parameter is `object` on purpose — these values arrive from JSON and HTML
        # forms, where "typed as int" means nothing until it is checked.
        _require_uint32("signature_id", self.signature_id)
        _require_uint32("gid", self.gid)


def _require_uint32(name: str, value: object) -> None:
    """Raise unless ``value`` is a plain integer that fits in 32 unsigned bits."""
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{name} must be an integer, got {type(value).__name__}"
        raise ValueError(msg)
    if not 0 <= value <= _UINT32_MAX:
        msg = f"{name} must fit in an unsigned 32-bit integer, got {value}"
        raise ValueError(msg)


class EveIngestor:
    """Turns Suricata EVE JSON records into Gilgamesh events."""

    name = "suricata"

    def __init__(
        self,
        database: Database | None = None,
        pipeline: Pipeline | None = None,
        severity_map: Mapping[int, Severity] | None = None,
    ) -> None:
        self._database = database
        self._pipeline = pipeline if pipeline is not None else Pipeline()
        self._severity_map = dict(severity_map or DEFAULT_SEVERITY_MAP)

    def parse_line(self, line: str) -> Event | None:
        """Parse one EVE line into an event, or ``None`` if it is not an alert."""
        return parse_eve_line(line, severity_map=self._severity_map)

    def ingest_line(self, line: str) -> bool:
        """Parse, pipeline, and store one line. Returns whether an event was stored."""
        event = self.parse_line(line)
        if event is None:
            return False
        return self._submit(event)

    def ingest_file(self, path: Path) -> int:
        """Ingest every alert in a finished EVE file. Returns how many were stored."""
        stored = 0
        for event in read_eve_events(path, severity_map=self._severity_map):
            if self._submit(event):
                stored += 1
        return stored

    def follow(self, path: Path, stop: StopSignal | None = None) -> Iterator[Event]:
        """Yield alerts as Suricata appends them to ``path``.

        ``stop`` is any object with an ``is_set()`` method; passing ``None`` follows
        forever. Intended to be called with ``threading.Event`` from the sensor service.

        At end-of-file the loop *sleeps* and retries, and re-opens the file when its
        inode changes — Suricata rotates ``eve.json`` by renaming, and a tailer that
        spins on an exhausted read burns the CPU the copy has to spare.

        A missing file is waited for rather than treated as an error: at boot the sensor
        normally starts before Suricata has created its log, and giving up there would
        silently disable Suricata ingestion until the next restart.
        """
        buffer = ""
        handle = None
        inode = -1
        try:
            while True:
                if stop is not None and stop.is_set():
                    return
                if handle is None:
                    try:
                        handle, inode = _open_following(path)
                    except OSError:
                        time.sleep(FOLLOW_POLL_SECONDS)
                        continue
                chunk = handle.read()
                if not chunk:
                    time.sleep(FOLLOW_POLL_SECONDS)
                    try:
                        current = path.stat()
                    except OSError:
                        continue
                    if current.st_ino != inode:
                        handle.close()
                        handle, inode = _open_following(path)
                        buffer = ""
                    continue
                buffer += chunk
                *lines, buffer = buffer.split("\n")
                for line in lines:
                    event = self.parse_line(line)
                    if event is not None:
                        yield event
        finally:
            if handle is not None:
                handle.close()

    def _submit(self, event: Event) -> bool:
        if self._pipeline.submit(event).decision is not PipelineDecision.STORE:
            return False
        if self._database is not None:
            self._database.insert_event(event)
        return True


def parse_eve_line(line: str, severity_map: Mapping[int, Severity] | None = None) -> Event | None:
    """Parse one EVE JSON line into an :class:`Event`, or return ``None``.

    Returns ``None`` — never raises — for blank lines, partial writes, non-JSON, and for
    every record type other than ``alert``. A tailer runs unattended, so a single bad
    line must not stop the sensor.
    """
    mapping = severity_map or DEFAULT_SEVERITY_MAP
    stripped = line.strip()
    if not stripped:
        return None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        logger.warning("skipping malformed EVE record: %s", stripped[:120])
        return None
    if not isinstance(parsed, dict):
        return None
    record = cast("dict[str, object]", parsed)
    if record.get("event_type") != "alert":
        return None

    alert_raw = record.get("alert")
    if not isinstance(alert_raw, dict):
        return None
    alert = cast("dict[str, object]", alert_raw)

    signature_id = alert.get("signature_id")
    if not isinstance(signature_id, int):
        logger.warning("skipping EVE alert without an integer signature_id")
        return None

    raw_severity = alert.get("severity")
    severity = (
        mapping.get(raw_severity, Severity.MEDIUM)
        if isinstance(raw_severity, int)
        else Severity.MEDIUM
    )

    return Event(
        type=EventType.SURICATA_ALERT,
        severity=severity,
        detector=EveIngestor.name,
        summary=str(alert.get("signature", "Suricata alert")),
        src_ip=_optional_str(record.get("src_ip")),
        dst_ip=_optional_str(record.get("dest_ip")),
        interface=_optional_str(record.get("in_iface")),
        details={
            "signature": alert.get("signature"),
            "signature_id": signature_id,
            "rev": alert.get("rev"),
            "gid": alert.get("gid"),
            "category": alert.get("category"),
            "action": alert.get("action"),
            "suricata_severity": raw_severity,
            "src_port": record.get("src_port"),
            "dest_port": record.get("dest_port"),
            "proto": record.get("proto"),
            "app_proto": record.get("app_proto"),
            "flow_id": record.get("flow_id"),
            "eve_event_type": record.get("event_type"),
        },
    )


def read_eve_events(
    path: Path, severity_map: Mapping[int, Severity] | None = None
) -> Iterator[Event]:
    """Yield every alert from a finished EVE file.

    A trailing line without a newline is ignored: it is a record still being written,
    and parsing half a line is how a tailer invents alerts.
    """
    if not path.exists():
        logger.warning("EVE file not found: %s", path)
        return
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.endswith("\n"):
                break
            event = parse_eve_line(line, severity_map=severity_map)
            if event is not None:
                yield event


def _render_conf(
    rules: Sequence[RuleSetting], enabled: bool, heading: str, path: Path | None
) -> str:
    """Render a suricata-update filter file, optionally writing it atomically.

    Lines beginning with ``#`` are skipped by suricata-update's parser, so the header
    uses ``#`` for comments while the directives themselves do not.
    """
    selected = sorted(
        (rule for rule in rules if rule.enabled is enabled),
        key=lambda rule: (rule.gid, rule.signature_id),
    )
    body = "\n".join(f"{rule.gid}:{rule.signature_id}" for rule in selected)
    content = f"# {heading}\n# Generated by Gilgamesh — do not edit by hand.\n{body}\n"
    if path is not None:
        _atomic_write(path, content)
    return content


def render_disable_conf(rules: Sequence[RuleSetting], path: Path | None = None) -> str:
    """Render ``disable.conf`` for the rules the owner has switched off."""
    return _render_conf(rules, enabled=False, heading="Gilgamesh disabled rules", path=path)


def render_enable_conf(rules: Sequence[RuleSetting], path: Path | None = None) -> str:
    """Render ``enable.conf`` for the rules the owner has explicitly switched on."""
    return _render_conf(rules, enabled=True, heading="Gilgamesh enabled rules", path=path)


def suricatasc_reload_command(unix_socket: Path | None = None) -> list[str]:
    """Return the argv for reloading rules, as a list — never a shell string.

    Gilgamesh does not execute this itself; it is surfaced to the operator and used by
    the systemd-triggered rules update.
    """
    command = ["suricatasc"]
    if unix_socket is not None:
        command += ["--unix-socket", str(unix_socket)]
    command += ["-c", "reload-rules"]
    return command


def _open_following(path: Path) -> tuple[IO[str], int]:
    """Open an EVE file for following, returning the handle and its inode.

    Suricata rotates ``eve.json`` by renaming it, so the tailer compares the inode and
    re-opens rather than reading a descriptor to a file nobody writes to any more.
    """
    handle = path.open(encoding="utf-8", errors="replace")
    return handle, path.stat().st_ino


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _atomic_write(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` via a temporary file and rename."""
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)
