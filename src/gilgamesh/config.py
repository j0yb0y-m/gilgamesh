"""Application settings.

The database is the single source of truth for *detection configuration* (decision
D-005); this class only carries process-level settings such as the data directory
and bind address. Values come from the environment with the ``GILGAMESH_`` prefix
so systemd units and development can share one code path.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process-level configuration."""

    model_config = SettingsConfigDict(env_prefix="GILGAMESH_", extra="ignore")

    data_dir: Path = Path("/var/lib/gilgamesh")
    # The owner reaches the UI from a browser on the LAN, so the server must bind
    # every address. This does not expose it beyond the management interface: the
    # two bridge members (eth0/eth1) are enslaved to br0 and hold no IP addresses
    # of their own, so only the bridge's management IP is reachable.
    host: str = "0.0.0.0"  # noqa: S104
    port: int = Field(default=8080, ge=1, le=65535)
    #: Hostnames/IPs the web app answers to, comma-separated. Defaults to ``*`` so a
    #: fresh install is reachable; set it to the management address to blunt DNS
    #: rebinding once the owner knows it (README documents this).
    allowed_hosts: str = "*"
    #: The interactive API docs (``/docs``) reveal the full route map; disabled by
    #: default and enabled only for a deliberate demo.
    enable_api_docs: bool = False
    #: Largest request body accepted, in bytes. Forms here carry a handful of short
    #: fields; anything bigger is an attempt to make the box allocate memory it does
    #: not have on an unauthenticated route.
    max_request_body_bytes: int = Field(default=65_536, ge=1024)
    #: The updater and the command socket used to reload rules after an update.
    suricata_update_command: str = "suricata-update"
    suricata_socket: Path = Path("/var/run/suricata/suricata-command.socket")
    #: Sensor-only: the interface to capture from (``br0`` in the documented
    #: inline deployment) or a recorded capture to replay instead. Exactly one of
    #: the two is required by ``gilgamesh-sensor``; the web tier never reads them.
    interface: str | None = None
    pcap: Path | None = None
    #: Sensor-only: the home gateway's address, used by the ARP detector's
    #: gateway-MAC check. When unset the sensor reads the default route itself.
    gateway_ip: str | None = None
    #: Sensor-only: Suricata's EVE JSON log to tail. When unset, Suricata
    #: ingestion is off and the custom detectors are the only source.
    suricata_eve_path: Path | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def db_path(self) -> Path:
        """Location of the SQLite database holding config, devices, and events."""
        return self.data_dir / "gilgamesh.db"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rules_version_path(self) -> Path:
        """Where the last successful rules update records its version."""
        return self.data_dir / "rules_version.txt"

    @property
    def host_allowlist(self) -> list[str]:
        """``allowed_hosts`` split into a list; never empty."""
        hosts = [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]
        return hosts if hosts else ["*"]
