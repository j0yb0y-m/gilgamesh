"""M9 — Suricata EVE JSON ingestion and rule-management tests.

Field names and the severity scale come from the Suricata 8 documentation
(``docs.suricata.io/en/latest/output/eve/eve-json-format.html``); the rule-filter file
format comes from ``suricata-update``'s own docs and source
(``doc/update.rst``, ``suricata/update/configs/disable.conf``, and the ``load_filters``
parser in ``suricata/update/main.py``).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Sequence
from pathlib import Path

import pytest

from gilgamesh.models import Event, EventType, Severity
from gilgamesh.sensors.suricata_ingest import (
    EveIngestor,
    RuleSetting,
    parse_eve_line,
    read_eve_events,
    render_disable_conf,
    render_enable_conf,
    suricatasc_reload_command,
)

SID = 2019401
GID = 1


def alert_line(
    *,
    severity: int = 1,
    signature: str = "ET MALWARE Test Signature",
    category: str = "Potentially Bad Traffic",
    src_ip: str = "10.0.0.2",
    dest_ip: str = "93.184.216.34",
    event_type: str = "alert",
) -> str:
    """Build one realistic EVE JSON line, using Suricata's real field names."""
    record: dict[str, object] = {
        "timestamp": "2026-10-14T09:00:00.123456+0000",
        "flow_id": 1234567890,
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": 51234,
        "dest_ip": dest_ip,
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
    }
    if event_type == "alert":
        record["alert"] = {
            "action": "allowed",
            "gid": GID,
            "signature_id": SID,
            "rev": 4,
            "signature": signature,
            "category": category,
            "severity": severity,
        }
    return json.dumps(record)


def test_alert_record_becomes_an_event() -> None:
    event = parse_eve_line(alert_line())

    assert event is not None
    assert event.type is EventType.SURICATA_ALERT
    assert event.detector == "suricata"
    assert event.details["signature"] == "ET MALWARE Test Signature"
    assert event.details["signature_id"] == SID
    assert event.details["category"] == "Potentially Bad Traffic"
    assert event.details["rev"] == 4
    assert event.details["action"] == "allowed"


def test_suricata_uses_dest_not_dst_for_the_destination() -> None:
    """EVE spells it ``dest_ip``/``dest_port``; getting this wrong loses the peer."""
    event = parse_eve_line(alert_line(src_ip="10.0.0.2", dest_ip="93.184.216.34"))

    assert event is not None
    assert event.src_ip == "10.0.0.2"
    assert event.dst_ip == "93.184.216.34"
    assert event.details["src_port"] == 51234
    assert event.details["dest_port"] == 443


def test_interface_is_recorded() -> None:
    record = json.loads(alert_line())
    record["in_iface"] = "br0"
    event = parse_eve_line(json.dumps(record))

    assert event is not None
    assert event.interface == "br0"


@pytest.mark.parametrize(
    ("suricata_severity", "expected"),
    [
        (1, Severity.CRITICAL),
        (2, Severity.HIGH),
        (3, Severity.MEDIUM),
        (4, Severity.LOW),
    ],
)
def test_severity_scale_is_mapped(suricata_severity: int, expected: Severity) -> None:
    event = parse_eve_line(alert_line(severity=suricata_severity))

    assert event is not None
    assert event.severity is expected


def test_unknown_severity_falls_back_to_medium() -> None:
    event = parse_eve_line(alert_line(severity=9))

    assert event is not None
    assert event.severity is Severity.MEDIUM


def test_severity_mapping_is_overridable() -> None:
    """The 1=highest direction is UNVERIFIED in the docs, so it must be changeable."""
    from gilgamesh.sensors.suricata_ingest import EveIngestor as Ingest

    ingest = Ingest(severity_map={1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH})
    event = ingest.parse_line(alert_line(severity=1))

    assert event is not None
    assert event.severity is Severity.LOW


def test_non_alert_records_are_ignored() -> None:
    for event_type in ("dns", "dhcp", "arp", "flow", "http"):
        assert parse_eve_line(alert_line(event_type=event_type)) is None


def test_malformed_json_is_ignored(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        assert parse_eve_line("{not json") is None
        assert parse_eve_line("") is None
        assert parse_eve_line("   ") is None

    assert any("eve" in record.getMessage().lower() for record in caplog.records)


def test_alert_without_alert_object_is_ignored() -> None:
    assert parse_eve_line(json.dumps({"event_type": "alert"})) is None


def test_read_events_skips_an_incomplete_trailing_line(tmp_path: Path) -> None:
    """A live tailer constantly sees a half-written final line; it must not crash."""
    path = tmp_path / "eve.json"
    path.write_text(f"{alert_line()}\n{alert_line()}\n" + '{"event_type": "alert", "aler')

    events = list(read_eve_events(path))

    assert len(events) == 2


def test_read_events_handles_a_missing_file(tmp_path: Path) -> None:
    assert list(read_eve_events(tmp_path / "absent.json")) == []


def test_read_events_copies_lines_into_the_evidence(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    path.write_text(alert_line() + "\n")

    events = list(read_eve_events(path))

    assert len(events) == 1
    assert events[0].details["eve_event_type"] == "alert"


def test_ingestor_persists_through_the_pipeline(tmp_path: Path) -> None:
    from gilgamesh.db import Database
    from gilgamesh.pipeline import Pipeline

    path = tmp_path / "eve.json"
    path.write_text("\n".join(alert_line() for _ in range(5)) + "\n")
    db = Database(tmp_path / "gilgamesh.db")
    db.initialize()
    ingestor = EveIngestor(database=db, pipeline=Pipeline())

    processed = ingestor.ingest_file(path)

    assert processed == 1
    assert len(db.list_events()) == 1
    db.close()


def test_disable_conf_uses_gid_sid_without_a_hash() -> None:
    """suricata-update skips lines starting with '#', so directives must not have one."""
    rules = [RuleSetting(signature_id=SID, enabled=False)]

    rendered = render_disable_conf(rules)

    assert f"{GID}:{SID}" in rendered
    assert "\n# 1:" not in rendered
    directive_lines = [line for line in rendered.splitlines() if line and not line.startswith("#")]
    assert directive_lines == [f"{GID}:{SID}"]


def test_enable_conf_contains_only_enabled_rules() -> None:
    rules = [
        RuleSetting(signature_id=2019401, enabled=True),
        RuleSetting(signature_id=2019402, enabled=False),
    ]

    enabled = render_enable_conf(rules)
    disabled = render_disable_conf(rules)

    assert "1:2019401" in enabled
    assert "1:2019402" not in enabled
    assert "1:2019402" in disabled
    assert "1:2019401" not in disabled


def test_rendered_directives_are_ordered_deterministically() -> None:
    rules = [
        RuleSetting(signature_id=300, enabled=False),
        RuleSetting(signature_id=100, enabled=False),
        RuleSetting(signature_id=200, enabled=False),
    ]

    assert render_disable_conf(rules) == render_disable_conf(list(reversed(rules)))


def test_non_integer_signature_ids_are_rejected() -> None:
    """Rule injection guard: a signature id is an int, so no rule text can reach the file.

    The type: ignore is deliberate — the point is that a value arriving from JSON or a
    form is not an int, and validation must reject it at runtime too.
    """
    with pytest.raises(ValueError):
        RuleSetting(
            signature_id="1:2000001; alert tcp any any -> any any (",  # type: ignore[arg-type]
            enabled=False,
        )


def test_out_of_range_signature_ids_are_rejected() -> None:
    with pytest.raises(ValueError):
        RuleSetting(signature_id=-1, enabled=False)
    with pytest.raises(ValueError):
        RuleSetting(signature_id=2**32, enabled=False)


def test_reload_command_is_a_list_not_a_shell_string() -> None:
    """Never hand a shell string to subprocess: keep it an argv list (safety rule)."""
    command = suricatasc_reload_command()

    assert command == ["suricatasc", "-c", "reload-rules"]
    assert isinstance(command, list)


def test_reload_command_can_target_a_custom_socket(tmp_path: Path) -> None:
    command = suricatasc_reload_command(unix_socket=tmp_path / "suricata-command.socket")

    assert "-c" in command
    assert str(tmp_path / "suricata-command.socket") in " ".join(command)


def test_render_conf_writes_files_atomically(tmp_path: Path) -> None:
    rules: Sequence[RuleSetting] = [RuleSetting(signature_id=SID, enabled=False)]
    target = tmp_path / "disable.conf"

    render_disable_conf(rules, path=target)

    assert target.exists()
    assert f"{GID}:{SID}" in target.read_text()


# --- following the live log ---------------------------------------------------
#
# The tailer runs in a thread started by the sensor service, so it must survive the two
# situations boot actually produces: Suricata has not created its log yet, and the file
# keeps growing afterwards. Both are driven here with a real thread and a poll interval
# shortened through the module constant, so the tests stay fast without changing code.


def _collect(ingestor: EveIngestor, path: Path, stop: threading.Event, out: list[Event]) -> None:
    for event in ingestor.follow(path, stop):
        out.append(event)


def test_follow_waits_for_a_log_that_appears_later(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At boot the sensor starts before Suricata; the tailer must not give up."""
    from gilgamesh.sensors import suricata_ingest

    monkeypatch.setattr(suricata_ingest, "FOLLOW_POLL_SECONDS", 0.02)
    path = tmp_path / "eve.json"
    stop = threading.Event()
    seen: list[Event] = []
    thread = threading.Thread(target=_collect, args=(EveIngestor(), path, stop, seen))
    thread.start()
    try:
        time.sleep(0.1)  # several polls with no file at all
        path.write_text(alert_line(signature="arrived after boot") + "\n")
        deadline = time.monotonic() + 5.0
        while not seen and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        stop.set()
        thread.join(timeout=5.0)

    assert not thread.is_alive()
    assert [event.details["signature"] for event in seen] == ["arrived after boot"]


def test_follow_yields_lines_appended_to_an_existing_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gilgamesh.sensors import suricata_ingest

    monkeypatch.setattr(suricata_ingest, "FOLLOW_POLL_SECONDS", 0.02)
    path = tmp_path / "eve.json"
    path.write_text(alert_line(signature="first") + "\n")
    stop = threading.Event()
    seen: list[Event] = []
    thread = threading.Thread(target=_collect, args=(EveIngestor(), path, stop, seen))
    thread.start()
    try:
        deadline = time.monotonic() + 5.0
        while len(seen) < 1 and time.monotonic() < deadline:
            time.sleep(0.02)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(alert_line(signature="second") + "\n")
        deadline = time.monotonic() + 5.0
        while len(seen) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        stop.set()
        thread.join(timeout=5.0)

    assert [event.details["signature"] for event in seen] == ["first", "second"]
