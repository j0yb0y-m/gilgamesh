"""Encrypt the provider API key at rest with a key file outside the database.

The database is copied for backups and read by the sensor process; the key file is
not. Keeping them separate means a copied ``gilgamesh.db`` cannot decrypt the token.
The file is written atomically and is readable only by the service account.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from gilgamesh.db import Database

logger = logging.getLogger(__name__)

_KEY_SETTING = "ai_api_key"


class AiKeyStore:
    """Store one API key encrypted in ``app_settings``.

    The Fernet key lives in ``key_path`` (``0600``); the encrypted token lives in
    the database. Either half alone is useless.
    """

    def __init__(self, database: Database, key_path: Path) -> None:
        self._db = database
        self._key_path = Path(key_path)

    def set_key(self, plaintext: str) -> None:
        """Encrypt and store ``plaintext``, creating the key file on first use."""
        value = plaintext.strip()
        if not value:
            raise ValueError("API key must not be empty")
        token = Fernet(self._ensure_key_file()).encrypt(value.encode("utf-8"))
        self._db.set_setting(_KEY_SETTING, token.decode("ascii"))

    def get_key(self) -> str | None:
        """The decrypted key, or ``None`` when unset or unreadable."""
        token = self._db.get_setting(_KEY_SETTING)
        if token is None:
            return None
        try:
            key = self._key_path.read_bytes()
            return Fernet(key).decrypt(token.encode("ascii")).decode("utf-8")
        except (OSError, ValueError, InvalidToken):
            logger.warning("AI key unavailable")
            return None

    def clear_key(self) -> None:
        """Delete the encrypted row. The key file stays for the next key."""
        self._db.execute("DELETE FROM app_settings WHERE key = ?", (_KEY_SETTING,))

    def is_set(self) -> bool:
        """Whether an encrypted row exists, even if it cannot be decrypted."""
        return self._db.get_setting(_KEY_SETTING) is not None

    def _ensure_key_file(self) -> bytes:
        """Return a valid key, generating and writing one when needed."""
        try:
            existing = self._key_path.read_bytes()
            Fernet(existing)
            return existing
        except (OSError, ValueError):
            pass
        directory = self._key_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        key = Fernet.generate_key()
        _atomic_write(self._key_path, key, mode=0o600)
        return key


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    """Write through a temporary name, so a crash cannot leave half a key."""
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    temporary.chmod(mode)
    os.replace(temporary, path)


__all__ = ["AiKeyStore"]
