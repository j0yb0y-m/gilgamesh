"""M13 — system health collection for the Health page.

C10 says the detectors must run without the Pi, and the same applies to the health page:
every probe reads from a *path*, so a test can point it at a temporary tree and assert
exactly what a Pi would report. A missing file must degrade to ``None``, never crash the
page — a health endpoint that 500s when something is absent is worse than useless.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from gilgamesh.health import collect_health


def _fake_proc(
    root: Path,
    *,
    mem_total: int = 4_000_000,
    mem_available: int = 3_000_000,
    uptime: str = "1234.50 9999.00",
) -> Path:
    proc = root / "proc"
    proc.mkdir(parents=True)
    (proc / "meminfo").write_text(
        f"MemTotal:       {mem_total} kB\n"
        f"MemFree:        {mem_available // 2} kB\n"
        f"MemAvailable:   {mem_available} kB\n",
        encoding="utf-8",
    )
    (proc / "uptime").write_text(uptime, encoding="utf-8")
    return proc


def _fake_sys(
    root: Path, *, temp_milli: int = 55_000, interfaces: dict[str, str] | None = None
) -> Path:
    sys_root = root / "sys"
    thermal = sys_root / "class" / "thermal" / "thermal_zone0"
    thermal.mkdir(parents=True)
    (thermal / "temp").write_text(f"{temp_milli}\n", encoding="utf-8")
    for name, state in (interfaces or {"eth0": "up", "eth1": "down"}).items():
        net = sys_root / "class" / "net" / name
        net.mkdir(parents=True)
        (net / "operstate").write_text(f"{state}\n", encoding="utf-8")
    return sys_root


def test_reads_memory_temperature_and_uptime(tmp_path: Path) -> None:
    proc = _fake_proc(tmp_path)
    sys_root = _fake_sys(tmp_path)

    report = collect_health(
        data_dir=tmp_path,
        proc=proc,
        sys=sys_root,
        interfaces=("eth0", "eth1"),
        loadavg=lambda: (0.5, 0.4, 0.3),
        disk_usage=_disk_usage_stub,
    )

    assert report.memory_total_kb == 4_000_000
    assert report.memory_available_kb == 3_000_000
    assert report.memory_used_percent == 25.0
    assert report.cpu_temp_c == 55.0
    assert report.uptime_seconds == 1234.5
    assert report.load_1m == 0.5


def test_reports_interface_operstate(tmp_path: Path) -> None:
    proc = _fake_proc(tmp_path)
    sys_root = _fake_sys(tmp_path)

    report = collect_health(
        data_dir=tmp_path,
        proc=proc,
        sys=sys_root,
        interfaces=("eth0", "eth1", "wlan9"),
        loadavg=lambda: (0.0, 0.0, 0.0),
        disk_usage=_disk_usage_stub,
    )

    states = {iface.name: iface.operstate for iface in report.interfaces}
    assert states == {"eth0": "up", "eth1": "down", "wlan9": "unknown"}


def test_reports_disk_from_the_injected_usage(tmp_path: Path) -> None:
    report = collect_health(
        data_dir=tmp_path,
        proc=_fake_proc(tmp_path),
        sys=_fake_sys(tmp_path),
        loadavg=lambda: (1.0, 2.0, 3.0),
        disk_usage=_disk_usage_stub,
    )

    assert report.disk_total_bytes == 1000
    assert report.disk_free_bytes == 400
    assert report.disk_used_percent == 60.0


def test_missing_files_degrade_to_none(tmp_path: Path) -> None:
    empty = tmp_path / "nowhere"
    empty.mkdir()

    report = collect_health(
        data_dir=tmp_path,
        proc=empty,
        sys=empty,
        interfaces=("eth0",),
        loadavg=lambda: (0.0, 0.0, 0.0),
        disk_usage=_disk_usage_stub,
    )

    assert report.memory_total_kb is None
    assert report.cpu_temp_c is None
    assert report.uptime_seconds is None
    assert report.interfaces[0].operstate == "unknown"


def test_last_event_and_rule_version_can_be_attached(tmp_path: Path) -> None:
    report = collect_health(
        data_dir=tmp_path,
        proc=_fake_proc(tmp_path),
        sys=_fake_sys(tmp_path),
        loadavg=lambda: (0.0, 0.0, 0.0),
        disk_usage=_disk_usage_stub,
    )

    stamped = report.with_context(
        last_event_ts=datetime(2026, 10, 14, 12, 0, tzinfo=UTC), rule_version="ET Open 2026-10-13"
    )

    assert stamped.last_event_ts == datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
    assert stamped.rule_version == "ET Open 2026-10-13"
    assert report.last_event_ts is None  # the original is untouched


def _disk_usage_stub(path: object) -> tuple[int, int, int]:
    """Stand-in for :func:`shutil.disk_usage`: 600 of 1000 bytes used."""
    return (1000, 600, 400)
