"""Deployment artifacts smoke tests."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_deploy_artifacts_exist() -> None:
    assert (REPO_ROOT / "install.sh").is_file()
    assert (REPO_ROOT / "deploy" / "systemd" / "gilgamesh-web.service").is_file()
    assert (REPO_ROOT / "deploy" / "systemd" / "gilgamesh-sensor.service").is_file()
    assert (REPO_ROOT / "deploy" / "systemd" / "gilgamesh-rules-update.service").is_file()
    assert (REPO_ROOT / "deploy" / "systemd" / "gilgamesh-rules-update.timer").is_file()
    assert (REPO_ROOT / "deploy" / "sysusers.d" / "gilgamesh.conf").is_file()
    assert (REPO_ROOT / "deploy" / "tmpfiles.d" / "gilgamesh.conf").is_file()
    assert (REPO_ROOT / "deploy" / "logrotate" / "gilgamesh").is_file()
    assert (REPO_ROOT / "deploy" / "suricata" / "suricata.service.d-gilgamesh.conf").is_file()
    assert (REPO_ROOT / "docs" / "DEMO.md").is_file()
