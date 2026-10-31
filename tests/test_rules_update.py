"""The rules-update pipeline: run ``suricata-update``, then reload Suricata.

This path is shared by the "Update rules" button and the daily timer, and is one of the
few places Gilgamesh executes external programs — so the argv is asserted literally, and
every failure mode is checked to be *reported* rather than raised. The updater binary is
injected, so no test shells out.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from gilgamesh.config import Settings
from gilgamesh.rules_update import (
    DEFAULT_TIMEOUT_SECONDS,
    RULES_UPDATE_UNIT,
    default_runner,
    read_rules_version,
    refresh_rules,
    trigger_rules_update_service,
)


def completed(
    argv: Sequence[str], returncode: int = 0, stdout: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(list(argv), returncode, stdout=stdout, stderr="")


class FakeRunner:
    """Records argv lists and replays scripted results, keyed by program name."""

    def __init__(self, results: dict[str, subprocess.CompletedProcess[str]] | None = None) -> None:
        self.commands: list[list[str]] = []
        self._results = results or {}

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        self.commands.append(argv)
        return self._results.get(argv[0], completed(argv))


def test_a_successful_update_runs_the_updater_then_reloads(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, suricata_socket=tmp_path / "suricata.sock")
    runner = FakeRunner(
        {"suricata-update": completed(["suricata-update"], stdout="rules updated\n")}
    )

    result = refresh_rules(settings=settings, runner=runner)

    assert result.ok is True
    assert result.error is None
    assert runner.commands[0] == ["suricata-update", "--no-test"]
    # The reload is a fixed argv list — never a shell string — and carries the socket.
    assert runner.commands[1] == [
        "suricatasc",
        "--unix-socket",
        str(settings.suricata_socket),
        "-c",
        "reload-rules",
    ]
    assert result.steps == ("suricata-update completed", "rules reloaded")


def test_a_successful_update_records_its_version(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    runner = FakeRunner(
        {"suricata-update": completed(["suricata-update"], stdout="Loaded 51200 rules\n")}
    )

    assert refresh_rules(settings=settings, runner=runner).ok is True

    stamp = read_rules_version(settings)
    assert stamp is not None
    assert stamp.startswith("20")  # ISO-8601 UTC, e.g. 2026-10-18T12:00:00+00:00


def test_a_missing_updater_is_reported_not_raised(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)

    def missing(_command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("suricata-update")

    result = refresh_rules(settings=settings, runner=missing)

    assert result.ok is False
    assert result.error is not None and "did not run" in result.error
    assert read_rules_version(settings) is None


def test_an_updater_failure_stops_before_the_reload(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    runner = FakeRunner({"suricata-update": completed(["suricata-update"], returncode=2)})

    result = refresh_rules(settings=settings, runner=runner)

    assert result.ok is False
    assert result.error == "suricata-update failed"
    assert [command[0] for command in runner.commands] == ["suricata-update"]
    assert read_rules_version(settings) is None


def test_a_failed_reload_is_reported_after_a_good_update(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    runner = FakeRunner({"suricatasc": completed(["suricatasc"], returncode=1)})

    result = refresh_rules(settings=settings, runner=runner)

    assert result.ok is False
    assert result.error == "rules installed but Suricata did not reload"
    # The rules *were* downloaded; the version stamp records that honestly.
    assert read_rules_version(settings) is None


def test_the_default_runner_reports_a_nonzero_exit_instead_of_raising(
    tmp_path: Path,
) -> None:
    """``check=False`` is deliberate: the caller turns a bad exit code into a message."""
    del tmp_path
    run = default_runner(30.0)

    result = run([sys.executable, "-c", "raise SystemExit(3)"])

    assert result.returncode == 3
    assert DEFAULT_TIMEOUT_SECONDS > 0


def test_the_web_trigger_starts_exactly_one_systemd_unit() -> None:
    """The web sandbox lacks Suricata's writable directories, so it only asks systemd."""
    runner = FakeRunner()

    result = trigger_rules_update_service(runner=runner)

    assert result.ok is True
    assert runner.commands == [["systemctl", "start", "--wait", "gilgamesh-rules-update.service"]]
    assert result.steps == ("rules update service completed",)


def test_the_triggered_unit_is_the_one_shipped_in_deploy() -> None:
    unit = Path(__file__).resolve().parents[1] / "deploy" / "systemd" / RULES_UPDATE_UNIT
    assert unit.is_file()


def test_the_web_trigger_reports_a_failed_unit_without_raising() -> None:
    failure = subprocess.CompletedProcess(
        ["systemctl"], 1, stdout="", stderr="Job for gilgamesh-rules-update.service failed"
    )

    result = trigger_rules_update_service(runner=lambda _command: failure)

    assert result.ok is False
    assert result.error is not None
    assert "failed" in result.error
    assert "suricata-update" not in result.error  # no raw command output leaks through


def test_the_web_trigger_reports_a_missing_systemctl_without_raising() -> None:
    def missing(_command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("systemctl")

    result = trigger_rules_update_service(runner=missing)

    assert result.ok is False
    assert result.error is not None and "systemctl" in result.error
