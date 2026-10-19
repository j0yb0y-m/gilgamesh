"""Update the Suricata rules and reload them.

This is the one place that turns "the rules may be out of date" into "the ruleset is
current", and both fronts call it: the ``gilgamesh-rules-update`` oneshot (run by a
daily systemd timer, and by hand) and the "Update rules" button on the Health page.
Keeping it in the library means the button and the unit can never drift apart.

Two things happen, in order, and any failure is *reported*, never raised:

1. ``suricata-update`` fetches and installs the ruleset;
2. ``suricatasc -c reload-rules`` tells a running Suricata to pick them up.

**Why the filter files are not touched.** ``disable.conf`` / ``enable.conf`` are
``suricata-update``'s per-signature filters, and Gilgamesh has no per-signature UI in
v1 — only the whole ``suricata.alerts`` rule. An earlier version of this module wrote
empty filter files on every run whenever no signature state existed, which silently
re-enabled every signature the deployment had disabled and overwrote local edits. The
files are therefore left exactly as the operator maintains them; when per-signature
control is implemented (D-017) its renderers are already in place and tested, in
``gilgamesh.sensors.suricata_ingest``.

Every external command is a fixed argv built by us — never a shell string, and never
anything that came from a request — and runs with a timeout.
"""

from __future__ import annotations

import contextlib
import logging
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from gilgamesh.config import Settings
from gilgamesh.sensors.suricata_ingest import suricatasc_reload_command
from gilgamesh.util.logging import configure_logging

#: A runner takes an argv list and returns the completed process. Injectable so tests
#: never shell out.
Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]

DEFAULT_TIMEOUT_SECONDS = 120.0

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RulesUpdateResult:
    """What a rules update did, step by step, and whether it all worked."""

    ok: bool
    steps: tuple[str, ...]
    error: str | None = None


def default_runner(timeout: float) -> Runner:
    """The real runner: a fixed argv, captured output, bounded by ``timeout``."""

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
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> RulesUpdateResult:
    """Run the updater, reload Suricata, and report the outcome."""
    run = runner if runner is not None else default_runner(timeout)
    steps: list[str] = []

    try:
        updater = run([settings.suricata_update_command, "--no-test"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("suricata-update did not run: %s", exc)
        return RulesUpdateResult(False, tuple(steps), f"suricata-update did not run: {exc}")
    if updater.returncode != 0:
        logger.warning("suricata-update exited %s", updater.returncode)
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
    # Not being able to write the stamp must not turn a good update into a failure.
    with contextlib.suppress(OSError):
        settings.rules_version_path.write_text(f"{stamp}\n{line}\n", encoding="utf-8")


def read_rules_version(settings: Settings) -> str | None:
    """The stamp written by the last successful update, or ``None``."""
    try:
        lines = settings.rules_version_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    return lines[0].strip() if lines else None


def main() -> None:
    """Entry point for ``gilgamesh-rules-update`` service.

    No database is needed any more: nothing about the ruleset depends on the owner's
    stored settings (only Suricata's own filters do, and those are left alone). The
    unit therefore runs without the state directory and reports failure by exit code.
    """
    configure_logging()
    settings = Settings()
    result = refresh_rules(settings=settings)
    if not result.ok:
        logger.error("rules update failed: %s", result.error)
        raise SystemExit(1)
    logger.info("rules update finished: %s", ", ".join(result.steps))


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "RulesUpdateResult",
    "default_runner",
    "main",
    "read_rules_version",
    "refresh_rules",
]
