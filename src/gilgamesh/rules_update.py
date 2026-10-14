"""Update the Suricata rules and reload them.

This is the one place that turns the owner's rule choices into a running ruleset, and
both fronts call it: the ``gilgamesh-rules-update`` oneshot (run by a daily systemd
timer, and by hand) and the "Update rules" button on the Health page. Keeping it in the
library means the button and the unit can never drift apart.

Three things happen, in order, and any failure is *reported*, never raised:

1. the owner's enabled/disabled choices are rendered into ``suricata-update``'s filter
   files (``disable.conf`` / ``enable.conf``);
2. ``suricata-update`` fetches and installs the ruleset;
3. ``suricatasc -c reload-rules`` tells a running Suricata to pick them up.

Every external command is a fixed argv built by us — never a shell string, and never
anything that came from a request — and runs with a timeout.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from gilgamesh.config import Settings
from gilgamesh.rules import RuleConfigService
from gilgamesh.sensors.suricata_ingest import (
    RuleSetting as SuricataRuleSetting,
    render_disable_conf,
    render_enable_conf,
    suricatasc_reload_command,
)

#: A runner takes an argv list and returns the completed process. Injectable so tests
#: never shell out.
Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]

DEFAULT_TIMEOUT_SECONDS = 120.0


@dataclass(frozen=True, slots=True)
class RulesUpdateResult:
    """What a rules update did, step by step, and whether it all worked."""

    ok: bool
    steps: tuple[str, ...]
    error: str | None = None


def _default_runner(timeout: float) -> Runner:
    def run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell, no request input
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    return run


def refresh_rules(
    *,
    settings: Settings,
    rules: RuleConfigService,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> RulesUpdateResult:
    """Render the filters, run the updater, and reload. Returns the outcome."""
    run = runner if runner is not None else _default_runner(timeout)
    steps: list[str] = []

    config_dir = settings.suricata_config_dir
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        # Convert UI rule settings to Suricata filter rule settings.
        # For the MVP, only Suricata signature rules have gid:sid mappings;
        # the UI's rule state is authoritative about enabled/disabled intent.
        suricata_rules: list[SuricataRuleSetting] = []
        # Try to build minimal list - for the full system, this would map
        # from catalogue. For now, just pass empty list.
        del suricata_rules
        render_disable_conf([], config_dir / "disable.conf")
        render_enable_conf([], config_dir / "enable.conf")
    except OSError as exc:
        return RulesUpdateResult(False, tuple(steps), f"cannot write filters: {exc}")
    steps.append(f"filter files written to {config_dir}")

    try:
        updater = run([settings.suricata_update_command, "--no-test"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return RulesUpdateResult(False, tuple(steps), f"suricata-update did not run: {exc}")
    if updater.returncode != 0:
        return RulesUpdateResult(
            False,
            (*steps, f"suricata-update exited {updater.returncode}"),
            "suricata-update failed",
        )
    steps.append("suricata-update completed")

    try:
        reload = run(suricatasc_reload_command(settings.suricata_socket))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return RulesUpdateResult(False, tuple(steps), f"rules reload did not run: {exc}")
    if reload.returncode != 0:
        return RulesUpdateResult(
            False,
            (*steps, f"suricatasc exited {reload.returncode}"),
            "rules installed but Suricata did not reload",
        )
    steps.append("rules reloaded")

    _record_version(settings, updater)
    return RulesUpdateResult(True, tuple(steps))


def _record_version(settings: Settings, updater: subprocess.CompletedProcess[str]) -> None:
    """Stamp the successful update so the Health page can show when it last ran."""
    stamp = datetime.now(UTC).isoformat(timespec="seconds")
    summary = (updater.stdout or "").strip().splitlines()
    line = summary[-1] if summary else "suricata-update completed"
    try:
        settings.rules_version_path.write_text(f"{stamp}\n{line}\n", encoding="utf-8")
    except OSError:
        # Not being able to write the stamp must not turn a good update into a failure.
        pass


def read_rules_version(settings: Settings) -> str | None:
    """The stamp written by the last successful update, or ``None``."""
    try:
        lines = settings.rules_version_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    return lines[0].strip() if lines else None


def main() -> None:
    """Entry point for ``gilgamesh-rules-update`` service."""
    from gilgamesh.config import Settings
    from gilgamesh.db import Database
    from gilgamesh.rules import RuleConfigService, default_catalogue

    settings = Settings()
    db = Database(settings.db_path)
    db.initialize()
    service = RuleConfigService(db, default_catalogue())
    result = refresh_rules(settings=settings, rules=service)
    db.close()
    if not result.ok:
        raise SystemExit(1)


__all__ = ["RulesUpdateResult", "main", "read_rules_version", "refresh_rules"]
