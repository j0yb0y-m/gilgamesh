"""System health probes for the Health page (M13).

Every value comes from a readable text file (``/proc``, ``/sys``) or a small injected
callable, never from a privileged API. That keeps two promises at once:

* **C10 / no Pi needed to test.** Paths and the disk/load sources are parameters, so a
  test builds a temporary tree that looks like a Pi and asserts the report.
* **The web tier stays unprivileged.** Nothing here needs a capability, so the health
  page can run in the hardened, capability-free unit (M14).

A probe that cannot read its file yields ``None`` rather than raising: a health page that
crashes because one sysfs node is missing tells the owner nothing about their box.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

#: A real Pi 4 exposes its SoC temperature here; some images use a different zone name.
_THERMAL_PATH = Path("class/thermal/thermal_zone0/temp")


class InterfaceStatus(BaseModel):
    """The link state of one capture/management interface."""

    model_config = ConfigDict(frozen=True)

    name: str
    operstate: str


class HealthReport(BaseModel):
    """Everything the Health page shows in one object."""

    model_config = ConfigDict(frozen=True)

    load_1m: float | None = None
    load_5m: float | None = None
    load_15m: float | None = None
    cpu_count: int | None = None
    cpu_temp_c: float | None = None
    uptime_seconds: float | None = None
    memory_total_kb: int | None = None
    memory_available_kb: int | None = None
    memory_used_percent: float | None = None
    disk_total_bytes: int | None = None
    disk_used_bytes: int | None = None
    disk_free_bytes: int | None = None
    disk_used_percent: float | None = None
    interfaces: tuple[InterfaceStatus, ...] = ()
    #: Filled by the route from the database and the rule files, not from ``/proc``.
    last_event_ts: datetime | None = None
    rule_version: str | None = None

    def with_context(
        self, *, last_event_ts: datetime | None, rule_version: str | None
    ) -> HealthReport:
        """Attach the sensor/rule facts the route looked up, leaving this report intact."""
        return self.model_copy(
            update={"last_event_ts": last_event_ts, "rule_version": rule_version}
        )


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _read_uptime(proc: Path) -> float | None:
    raw = _read_text(proc / "uptime")
    if raw is None:
        return None
    try:
        return float(raw.split()[0])
    except (IndexError, ValueError):
        return None


def _read_memory(proc: Path) -> tuple[int | None, int | None, float | None]:
    raw = _read_text(proc / "meminfo")
    if raw is None:
        return None, None, None
    fields: dict[str, int] = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].rstrip(":") in {"MemTotal", "MemAvailable"}:
            try:
                fields[parts[0].rstrip(":")] = int(parts[1])
            except ValueError:
                continue
    total, available = fields.get("MemTotal"), fields.get("MemAvailable")
    used_percent = None
    if total and available is not None:
        used_percent = round(100.0 * (total - available) / total, 1)
    return total, available, used_percent


def _read_temp(sys_root: Path) -> float | None:
    milli = _read_int(sys_root / _THERMAL_PATH)
    return round(milli / 1000.0, 1) if milli is not None else None


def _read_interfaces(sys_root: Path, names: Sequence[str]) -> tuple[InterfaceStatus, ...]:
    statuses: list[InterfaceStatus] = []
    for name in names:
        state = _read_text(sys_root / "class" / "net" / name / "operstate") or "unknown"
        statuses.append(InterfaceStatus(name=name, operstate=state))
    return tuple(statuses)


def _read_disk(
    path: Path, usage: Callable[[Path], tuple[int, int, int]]
) -> tuple[int | None, int | None, int | None, float | None]:
    try:
        total, used, free = usage(path)
    except OSError:
        return None, None, None, None
    used_percent = round(100.0 * used / total, 1) if total else None
    return total, used, free, used_percent


def collect_health(
    *,
    data_dir: Path,
    proc: Path = Path("/proc"),
    sys: Path = Path("/sys"),
    interfaces: Sequence[str] = (),
    loadavg: Callable[[], tuple[float, float, float]] | None = None,
    disk_usage: Callable[[Path], tuple[int, int, int]] | None = None,
) -> HealthReport:
    """Build a :class:`HealthReport`, tolerating anything that cannot be read."""
    import os
    import shutil

    load: tuple[float | None, float | None, float | None] = (None, None, None)
    get_load = loadavg if loadavg is not None else os.getloadavg
    values = get_load()
    load = (values[0], values[1], values[2])

    total_kb, available_kb, memory_percent = _read_memory(proc)
    disk_total, disk_used, disk_free, disk_percent = _read_disk(
        data_dir, disk_usage if disk_usage is not None else shutil.disk_usage
    )

    return HealthReport(
        load_1m=load[0],
        load_5m=load[1],
        load_15m=load[2],
        cpu_count=os.cpu_count(),
        cpu_temp_c=_read_temp(sys),
        uptime_seconds=_read_uptime(proc),
        memory_total_kb=total_kb,
        memory_available_kb=available_kb,
        memory_used_percent=memory_percent,
        disk_total_bytes=disk_total,
        disk_used_bytes=disk_used,
        disk_free_bytes=disk_free,
        disk_used_percent=disk_percent,
        interfaces=_read_interfaces(sys, interfaces),
    )


__all__ = ["HealthReport", "InterfaceStatus", "collect_health"]
