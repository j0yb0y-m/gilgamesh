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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def db_path(self) -> Path:
        """Location of the SQLite database holding config, devices, and events."""
        return self.data_dir / "gilgamesh.db"
