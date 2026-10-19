"""Deployment artifacts: the units, the accounts, and the installer.

These are the files that only ever run on the Pi, so they get the cheapest possible
verification here: every artifact is parsed or read as text, the installer is syntax
checked, and — when the development machine has systemd and shellcheck — the units are
handed to ``systemd-analyze verify`` and the script to ``shellcheck``.

The drift that matters is checked by content: the units must start the console scripts
this project actually defines, the two service accounts must both exist (the web unit
cannot start as a user nobody creates), and the database directory must stay 0770 with a
group both processes share. Each of those was once wrong in this repository, and each
would only have shown up as a failed boot on the Pi.
"""

from __future__ import annotations

import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY = REPO_ROOT / "deploy"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# --- the artifacts exist ------------------------------------------------------


def test_deploy_artifacts_exist() -> None:
    assert (REPO_ROOT / "install.sh").is_file()
    assert (DEPLOY / "systemd" / "gilgamesh-web.service").is_file()
    assert (DEPLOY / "systemd" / "gilgamesh-sensor.service").is_file()
    assert (DEPLOY / "systemd" / "gilgamesh-rules-update.service").is_file()
    assert (DEPLOY / "systemd" / "gilgamesh-rules-update.timer").is_file()
    assert (DEPLOY / "sysusers.d" / "gilgamesh.conf").is_file()
    assert (DEPLOY / "journald" / "10-gilgamesh.conf").is_file()
    assert (DEPLOY / "suricata" / "10-gilgamesh.conf").is_file()
    assert (DEPLOY / "gilgamesh.env.example").is_file()
    assert (REPO_ROOT / "docs" / "DEMO.md").is_file()


def test_installer_is_executable_and_syntactically_valid() -> None:
    script = REPO_ROOT / "install.sh"
    assert script.stat().st_mode & 0o111, "install.sh must be executable"

    # Fixed argv, absolute interpreter, no shell: the only input is our own file path.
    result = subprocess.run(  # noqa: S603 - fixed argv
        [BASH, "-n", str(script)], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr


def test_installer_obeys_the_projects_hard_rules() -> None:
    """No pip, no sudo, no download-and-pipe-to-shell, no OS package manager."""
    text = read(REPO_ROOT / "install.sh")

    for forbidden in ("pip install", "python -m venv", "curl", "wget", "apt-get install", "pipx"):
        assert forbidden not in text, f"install.sh must not contain {forbidden!r}"
    for line in text.splitlines():
        assert not line.strip().startswith("sudo "), f"install.sh must never invoke sudo: {line!r}"
    assert "set -euo pipefail" in text, "an installer that keeps going after a failure is a trap"


# --- accounts and directories -------------------------------------------------


def test_sysusers_creates_both_service_accounts() -> None:
    text = read(DEPLOY / "sysusers.d" / "gilgamesh.conf")

    assert "u! gilgamesh" in text, "the web unit runs as gilgamesh; that user must exist"
    assert "u! gilgamesh-sensor" in text
    assert "m  gilgamesh-sensor gilgamesh" in text, "the sensor needs the shared group"


def test_no_tmpfiles_fragment_is_shipped() -> None:
    """Nothing needs a tmpfiles-managed directory any more.

    The sensor and the web process share the database, not a runtime socket, so an
    earlier /run/gilgamesh fragment was dead configuration that only widened access.
    """
    assert not (DEPLOY / "tmpfiles.d").exists()


def test_no_logrotate_fragment_is_shipped() -> None:
    """All three services log to the journal, and journald's own caps bound it.

    An earlier deploy/logrotate/gilgamesh fragment had nothing left to rotate once the
    design moved every log stream to journald — dead configuration, removed.
    """
    assert not (DEPLOY / "logrotate").exists()


# --- the units ----------------------------------------------------------------


def unit(name: str) -> str:
    return read(DEPLOY / "systemd" / name)


def test_units_start_the_console_scripts_this_project_defines() -> None:
    project = tomllib.loads(read(REPO_ROOT / "pyproject.toml"))
    scripts = set(project["project"]["scripts"])

    for name, script in (
        ("gilgamesh-web.service", "gilgamesh-web"),
        ("gilgamesh-sensor.service", "gilgamesh-sensor"),
        ("gilgamesh-rules-update.service", "gilgamesh-rules-update"),
    ):
        text = unit(name)
        assert script in scripts
        assert f"ExecStart=/opt/gilgamesh/.venv/bin/{script}" in text
        assert "EnvironmentFile=/etc/gilgamesh/gilgamesh.env" in text


def test_web_unit_keeps_the_database_private() -> None:
    text = unit("gilgamesh-web.service")

    assert "User=gilgamesh" in text
    assert "StateDirectory=gilgamesh" in text
    assert "StateDirectoryMode=0770" in text
    assert "UMask=0007" in text
    assert "ProtectSystem=strict" in text


def test_sensor_unit_shares_exactly_the_database_directory() -> None:
    text = unit("gilgamesh-sensor.service")

    assert "User=gilgamesh-sensor" in text
    assert "SupplementaryGroups=gilgamesh" in text
    assert "ReadWritePaths=/var/lib/gilgamesh" in text
    assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" in text
    assert "ProtectSystem=strict" in text


def test_rules_update_unit_can_write_its_stamp_and_suricata_rules() -> None:
    text = unit("gilgamesh-rules-update.service")

    assert "Type=oneshot" in text
    assert "ReadWritePaths=/var/lib/gilgamesh" in text
    assert "/var/lib/suricata" in text


def test_timer_runs_daily_and_is_persistent() -> None:
    text = unit("gilgamesh-rules-update.timer")

    assert "OnCalendar=" in text
    assert "Persistent=true" in text
    assert "WantedBy=timers.target" in text


def test_suricata_dropin_uses_the_numbered_drop_in_name() -> None:
    """systemd reads drop-ins in lexical order; the number is the convention."""
    assert (DEPLOY / "suricata" / "10-gilgamesh.conf").is_file()
    assert not (DEPLOY / "suricata" / "suricata.service.d-gilgamesh.conf").exists()


def test_environment_example_names_every_process_setting() -> None:
    text = read(DEPLOY / "gilgamesh.env.example")

    assert "GILGAMESH_DATA_DIR=/var/lib/gilgamesh" in text
    assert "GILGAMESH_INTERFACE=br0" in text
    assert "GILGAMESH_SURICATA_EVE_PATH=/var/log/suricata/eve.json" in text


def test_journald_caps_bound_the_log() -> None:
    text = read(DEPLOY / "journald" / "10-gilgamesh.conf")

    assert "[Journal]" in text
    assert "SystemMaxUse=" in text
    assert "MaxRetentionSec=" in text


# --- platform tools, when the machine has them --------------------------------

SYSTEMD_ANALYZE = shutil.which("systemd-analyze")
SHELLCHECK = shutil.which("shellcheck")
BASH = shutil.which("bash") or "/bin/bash"

#: `systemd-analyze verify` also checks that ExecStart= exists on *this* machine. The
#: virtualenv only exists on the target, so that one message is expected and ignored.
_EXPECTED_VERIFY_NOISE = "is not executable: No such file or directory"


@pytest.mark.skipif(SYSTEMD_ANALYZE is None, reason="systemd-analyze not available")
def test_units_verify_cleanly_under_systemd_analyze() -> None:
    units = sorted((DEPLOY / "systemd").glob("*.service"))
    assert SYSTEMD_ANALYZE is not None  # guaranteed by the skipif above
    result = subprocess.run(  # noqa: S603 - fixed argv, absolute path
        [SYSTEMD_ANALYZE, "verify", *map(str, units)],
        capture_output=True,
        text=True,
        check=False,
    )

    unexpected = [
        line
        for line in result.stderr.splitlines()
        if line.strip() and _EXPECTED_VERIFY_NOISE not in line
    ]
    assert unexpected == []


@pytest.mark.skipif(SHELLCHECK is None, reason="shellcheck not available")
def test_installer_passes_shellcheck() -> None:
    assert SHELLCHECK is not None  # guaranteed by the skipif above
    result = subprocess.run(  # noqa: S603 - fixed argv, absolute path
        [SHELLCHECK, "install.sh"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout
