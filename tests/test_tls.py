"""Optional web TLS: the setting must actually change what Uvicorn serves.

``https_mode`` is stored on the Settings page but used to be inert: the process always
spoke plain HTTP. These tests pin the three modes down — off stays off, self-signed
generates and reuses a real certificate/key pair under the state directory, and
provided mode insists on an explicit pair rather than silently falling back to HTTP.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509

from gilgamesh.config import Settings
from gilgamesh.db import Database
from gilgamesh.preferences import Preferences, PreferencesStore
from gilgamesh.web import server
from gilgamesh.web.tls import TlsConfigError, resolve_tls_config


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return Settings(data_dir=tmp_path, **overrides)  # type: ignore[arg-type]


def test_https_off_returns_no_tls_and_writes_nothing(tmp_path: Path) -> None:
    config = resolve_tls_config(_settings(tmp_path), Preferences(https_mode="off"))

    assert config is None
    assert not (tmp_path / "tls").exists()


def test_self_signed_mode_generates_a_real_certificate_and_private_key(
    tmp_path: Path,
) -> None:
    config = resolve_tls_config(
        _settings(tmp_path, tls_hostname="gilgamesh.lan"),
        Preferences(https_mode="self-signed"),
    )

    assert config is not None
    assert config.certfile == tmp_path / "tls" / "cert.pem"
    assert config.keyfile == tmp_path / "tls" / "key.pem"

    certificate = x509.load_pem_x509_certificate(config.certfile.read_bytes())
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_names = {name.lower() for name in san.get_values_for_type(x509.DNSName)}
    addresses = set(san.get_values_for_type(x509.IPAddress))

    assert "gilgamesh.lan" in dns_names
    assert "localhost" in dns_names
    assert ipaddress.ip_address("127.0.0.1") in addresses
    assert certificate.not_valid_after_utc > datetime.now(UTC)
    # The private key must not be world-readable.
    assert config.keyfile.stat().st_mode & 0o777 == 0o600


def test_self_signed_mode_reuses_a_usable_certificate(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    first = resolve_tls_config(settings, Preferences(https_mode="self-signed"))
    assert first is not None
    original_cert = first.certfile.read_bytes()
    original_key = first.keyfile.read_bytes()

    second = resolve_tls_config(settings, Preferences(https_mode="self-signed"))

    assert second is not None
    assert second.certfile.read_bytes() == original_cert
    assert second.keyfile.read_bytes() == original_key


def test_provided_mode_requires_both_explicit_paths(tmp_path: Path) -> None:
    with pytest.raises(TlsConfigError, match="GILGAMESH_TLS_CERTFILE"):
        resolve_tls_config(_settings(tmp_path), Preferences(https_mode="provided"))


def test_provided_mode_uses_the_configured_pair(tmp_path: Path) -> None:
    generated = resolve_tls_config(_settings(tmp_path), Preferences(https_mode="self-signed"))
    assert generated is not None
    settings = _settings(tmp_path, tls_certfile=generated.certfile, tls_keyfile=generated.keyfile)

    config = resolve_tls_config(settings, Preferences(https_mode="provided"))

    assert config is not None
    assert config.certfile == generated.certfile
    assert config.keyfile == generated.keyfile


def test_provided_mode_reports_a_missing_file(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        tls_certfile=tmp_path / "absent-cert.pem",
        tls_keyfile=tmp_path / "absent-key.pem",
    )

    with pytest.raises(TlsConfigError, match=r"absent-cert\.pem"):
        resolve_tls_config(settings, Preferences(https_mode="provided"))


def _seed_preferences(data_dir: Path, mode: str) -> None:
    database = Database(data_dir / "gilgamesh.db")
    database.initialize()
    PreferencesStore(database).update(https_mode=mode)
    database.close()


def test_main_passes_the_generated_certificate_to_uvicorn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_preferences(tmp_path, "self-signed")
    monkeypatch.setenv("GILGAMESH_DATA_DIR", str(tmp_path))
    captured: dict[str, object] = {}

    def fake_run(app: object, **kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(server.uvicorn, "run", fake_run)

    server.main()

    assert captured["ssl_certfile"] == str(tmp_path / "tls" / "cert.pem")
    assert captured["ssl_keyfile"] == str(tmp_path / "tls" / "key.pem")


def test_main_keeps_plain_http_when_the_owner_chose_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_preferences(tmp_path, "off")
    monkeypatch.setenv("GILGAMESH_DATA_DIR", str(tmp_path))
    captured: dict[str, object] = {}

    def fake_run(app: object, **kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(server.uvicorn, "run", fake_run)

    server.main()

    assert "ssl_certfile" not in captured
    assert "ssl_keyfile" not in captured
