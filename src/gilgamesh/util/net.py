"""Helpers for normalising the network values that flow through detectors.

Detectors compare MAC addresses constantly, and the same address can reach them in
different textual forms (``AA-BB-CC-00-00:01``, ``aa:bb:cc:00:00:01``). Comparing raw
strings would silently miss spoofing, so every MAC is normalised once, on the way in.
"""

from __future__ import annotations

MAC_ZERO = "00:00:00:00:00:00"
# ruff's S104 flags any "0.0.0.0" literal as "binding to all interfaces". This is the
# IPv4 unspecified address used to recognise ARP probes, not a bind address.
IPV4_ZERO = "0.0.0.0"  # noqa: S104


def normalize_mac(value: str) -> str:
    """Return ``value`` as a lower-case colon-separated MAC address.

    Accepts dash-separated input. Raises :class:`ValueError` for anything that is not
    exactly six two-digit hex octets — a malformed address is a bug or an attack
    signal, and silently passing it through would corrupt a binding table.
    """
    parts = value.strip().lower().replace("-", ":").split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ValueError(f"not a MAC address: {value!r}")
    try:
        return ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError as exc:
        raise ValueError(f"not a MAC address: {value!r}") from exc


def is_valid_mac(value: str) -> bool:
    """Return whether ``value`` is a well-formed MAC address."""
    try:
        normalize_mac(value)
    except ValueError:
        return False
    return True
