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
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from gilgamesh.db import Database
from gilgamesh.models import Event, EventType, Severity
from gilgamesh.pipeline import Pipeline, PipelineDecision
from gilgamesh.sensors.eve_tail import StopSignal, follow_json_lines

logger = logging.getLogger(__name__)

#: ``app_settings`` prefix for the last safely-consumed position in an EVE file. One row
#: per path so a deployment that points the sensor at a different log starts clean.
#: Behaviour uses its own prefix so the two readers never move each other's position.
POSITION_KEY_PREFIX = "suricata_eve_position:"


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

        The durable mechanics — start at the end on first open, resume a persisted
        inode/offset, wait for a missing file, rewind a partial line, reopen at byte
        zero after rotation, and save the position only after the consumer takes the
        record — live in :func:`~gilgamesh.sensors.eve_tail.follow_json_lines`. This
        method only interprets each record as an alert.

        The position key stays alert-specific (``suricata_eve_position:``), so another
        reader can follow the same file under its own key without moving this one.
        """
        for record in follow_json_lines(
            path,
            database=self._database,
            position_key=f"{POSITION_KEY_PREFIX}{path}",
            stop=stop,
        ):
            event = parse_eve_record(record, severity_map=self._severity_map)
            if event is not None:
                yield event

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
    return parse_eve_record(cast("dict[str, object]", parsed), severity_map=severity_map)


def parse_eve_record(
    record: Mapping[str, object], severity_map: Mapping[int, Severity] | None = None
) -> Event | None:
    """Turn one decoded EVE record into an :class:`Event`, or return ``None``.

    Only ``alert`` records become events. ``flow``, ``dns`` and the rest are facts for
    other readers, not verdicts, and are ignored here. An alert without an integer
    ``signature_id`` cannot be attributed to a rule and is skipped with a warning.
    """
    mapping = severity_map or DEFAULT_SEVERITY_MAP
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
        ts=_parse_timestamp(record.get("timestamp")),
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


def _parse_timestamp(value: object) -> datetime:
    """Suricata's ISO-8601 timestamp, or the current time when it is unusable.

    EVE writes ``2026-10-14T09:00:00.123456+0000``. ``datetime.fromisoformat`` accepts
    that shape on Python 3.13; a malformed value must not drop the alert, so it falls
    back to "now" and the record's other evidence still reaches the owner.
    """
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            pass
        else:
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _atomic_write(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` via a temporary file and rename."""
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)
