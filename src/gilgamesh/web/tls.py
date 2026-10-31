"""TLS termination for the web UI.

The Settings page stores the owner's intent (``https_mode`` = ``off``, ``self-signed``,
or ``provided``). This module is the one place that turns that intent into the
``ssl_certfile``/``ssl_keyfile`` options Uvicorn needs, so the setting is no longer a
label that changes nothing.

**Self-signed mode** keeps its certificate under the state directory
(``<data_dir>/tls/cert.pem`` and ``key.pem``). The key is written ``0600`` and the
directory ``0700``; the certificate is re-generated when it is missing, corrupt, about
to expire, or does not cover the names the owner actually uses. A self-signed
certificate still makes the browser warn — that is the nature of a certificate no
public CA signed — but the traffic is encrypted, which is the point.

**Provided mode** never copies or rewrites the owner's files. It reads the paths from
``GILGAMESH_TLS_CERTFILE`` and ``GILGAMESH_TLS_KEYFILE`` and fails loudly if either is
missing, because silently serving plain HTTP after the owner asked for HTTPS is a
security downgrade.

**Off mode** is deliberately unchanged: plain HTTP on the LAN, the default for a home
appliance.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import socket
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gilgamesh.config import Settings
from gilgamesh.preferences import Preferences

logger = logging.getLogger(__name__)

CERTIFICATE_FILENAME = "cert.pem"
PRIVATE_KEY_FILENAME = "key.pem"
#: Regenerate this long before expiry, so an appliance that is rarely restarted still
#: never serves a certificate that is about to lapse.
RENEW_BEFORE = timedelta(days=30)
#: 397 days is the maximum Apple accepts for a server certificate.
VALID_FOR = timedelta(days=397)


class TlsConfigError(RuntimeError):
    """The selected HTTPS mode cannot be served. The message is safe to log."""


@dataclass(frozen=True, slots=True)
class TlsConfig:
    """The certificate and key Uvicorn should serve."""

    certfile: Path
    keyfile: Path


def resolve_tls_config(settings: Settings, preferences: Preferences) -> TlsConfig | None:
    """Return the TLS files for the owner's chosen mode, or ``None`` for plain HTTP."""
    mode = preferences.https_mode
    if mode == "off":
        return None

    if mode == "self-signed":
        directory = settings.data_dir / "tls"
        certfile = directory / CERTIFICATE_FILENAME
        keyfile = directory / PRIVATE_KEY_FILENAME
        names = _certificate_names(settings)
        if not _certificate_is_usable(certfile, keyfile, names):
            logger.info("generating a self-signed TLS certificate in %s", directory)
            try:
                generate_self_signed_certificate(certfile, keyfile, names=names)
            except OSError as exc:
                msg = f"could not create the self-signed certificate in {directory}: {exc}"
                raise TlsConfigError(msg) from exc
        return TlsConfig(certfile, keyfile)

    if mode == "provided":
        certfile = settings.tls_certfile
        keyfile = settings.tls_keyfile
        if certfile is None or keyfile is None:
            msg = (
                "HTTPS is set to 'provided', but GILGAMESH_TLS_CERTFILE and "
                "GILGAMESH_TLS_KEYFILE are not both set."
            )
            raise TlsConfigError(msg)
        for label, path in (("certificate", certfile), ("private key", keyfile)):
            if not path.is_file():
                msg = f"HTTPS is set to 'provided', but the {label} does not exist: {path}"
                raise TlsConfigError(msg)
        return TlsConfig(certfile, keyfile)

    msg = f"unknown HTTPS mode: {mode!r}"
    raise TlsConfigError(msg)


def generate_self_signed_certificate(
    certfile: Path,
    keyfile: Path,
    *,
    names: Sequence[str] = (),
) -> None:
    """Write a fresh self-signed certificate and private key.

    ``names`` are extra DNS names or IP addresses for the subject alternative name
    extension. ``localhost``, ``127.0.0.1`` and ``::1`` are always included.
    """
    directory = certfile.parent
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)

    now = datetime.now(UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    entries = _subject_alt_names(names)
    common_name = _common_name(names)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + VALID_FOR)
        .add_extension(x509.SubjectAlternativeName(entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    _atomic_write(
        keyfile,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        mode=0o600,
    )
    _atomic_write(
        certfile,
        certificate.public_bytes(serialization.Encoding.PEM),
        mode=0o644,
    )


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    """Write a file through a temporary name, so a crash cannot leave half a key."""
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    temporary.chmod(mode)
    temporary.replace(path)


def _certificate_names(settings: Settings) -> list[str]:
    """Names the generated certificate should cover on this machine."""
    names: list[str] = ["localhost", "127.0.0.1", "::1"]
    if settings.tls_hostname:
        names.extend(part.strip() for part in settings.tls_hostname.split(",") if part.strip())
    try:
        hostname = socket.gethostname()
    except OSError:
        return names
    if hostname:
        names.append(hostname)
        with contextlib.suppress(OSError):
            names.append(socket.getfqdn(hostname))
        try:
            _, _, addresses = socket.gethostbyname_ex(hostname)
        except OSError:
            addresses = []
        names.extend(addresses)
    return names


def _subject_alt_names(names: Sequence[str]) -> list[x509.GeneralName]:
    """Turn a mixed list of hostnames and addresses into SAN entries, deduplicated."""
    entries: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    seen_dns = {"localhost"}
    seen_addresses = {"127.0.0.1", "::1"}
    for name in names:
        try:
            address = ipaddress.ip_address(name)
        except ValueError:
            key = name.lower()
            if key not in seen_dns and 0 < len(name) <= 253:
                entries.append(x509.DNSName(name))
                seen_dns.add(key)
        else:
            key = str(address)
            if key not in seen_addresses:
                entries.append(x509.IPAddress(address))
                seen_addresses.add(key)
    return entries


def _common_name(names: Sequence[str]) -> str:
    """A short, human-readable subject; the SAN list is what clients actually check."""
    primary = next(
        (name for name in names if not _is_address(name) and name.lower() != "localhost"),
        "gilgamesh",
    )
    return primary[:64]


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _certificate_is_usable(certfile: Path, keyfile: Path, names: Sequence[str]) -> bool:
    """Whether the existing pair is intact, current, matching, and covers ``names``."""
    try:
        certificate = x509.load_pem_x509_certificate(certfile.read_bytes())
        key = serialization.load_pem_private_key(keyfile.read_bytes(), password=None)
    except (OSError, ValueError):
        return False

    if certificate.not_valid_after_utc - RENEW_BEFORE <= datetime.now(UTC):
        return False

    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_public != key_public:
        return False

    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False

    covered_dns = {name.lower() for name in san.get_values_for_type(x509.DNSName)}
    covered_addresses = {str(address) for address in san.get_values_for_type(x509.IPAddress)}
    for name in names:
        try:
            address = ipaddress.ip_address(name)
        except ValueError:
            if name.lower() not in covered_dns:
                return False
        else:
            if str(address) not in covered_addresses:
                return False
    return True
