"""Attribute EVE addresses to inventory devices, and classify where they live.

The behaviour engine only scores traffic it can tie to a device. Attribution is
deliberately conservative: an address that is not in the inventory is skipped
rather than guessed, so a new or spoofed address cannot inherit another device's
baseline.

Classification answers two separate questions:

* **internal** — RFC 1918, IPv6 ULA, or an explicitly configured LAN prefix.
* **external** — anything else that is not loopback, link-local, multicast,
  broadcast, or unspecified. CGNAT and documentation ranges are external for this
  purpose; a home network's traffic to them still leaves the LAN.

Loopback, link-local, multicast, broadcast, and unspecified addresses are neither:
they are not useful peers for volume or destination scoring.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence

from gilgamesh.devices import DeviceRecord

LanPrefix = ipaddress.IPv4Network | ipaddress.IPv6Network

_PRIVATE_V4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_PRIVATE_V6: tuple[ipaddress.IPv6Network, ...] = (ipaddress.IPv6Network("fc00::/7"),)
_BROADCAST_V4 = ipaddress.IPv4Address("255.255.255.255")


class DeviceMap:
    """A bounded IP → MAC map built from the device inventory."""

    def __init__(
        self,
        *,
        lan_prefixes: Sequence[LanPrefix] = (),
        max_entries: int = 10_000,
    ) -> None:
        self._lan_prefixes = tuple(lan_prefixes)
        self._max_entries = max(0, max_entries)
        self._by_ip: dict[str, str] = {}
        self._by_mac: dict[str, DeviceRecord] = {}

    def refresh(self, devices: Iterable[DeviceRecord]) -> None:
        """Rebuild the map from ``devices``, most recently seen first.

        When two devices claim the same address the first one wins; callers pass
        :meth:`DeviceStore.list`, which is ordered most-recent-first.
        """
        by_ip: dict[str, str] = {}
        by_mac: dict[str, DeviceRecord] = {}
        for record in devices:
            by_mac[record.mac] = record
            for raw in record.ips:
                address = _parse(raw)
                if address is None:
                    continue
                key = str(address)
                if key in by_ip:
                    continue
                if len(by_ip) >= self._max_entries:
                    self._by_ip = by_ip
                    self._by_mac = by_mac
                    return
                by_ip[key] = record.mac
        self._by_ip = by_ip
        self._by_mac = by_mac

    def record(self, mac: str) -> DeviceRecord | None:
        """The inventory record for ``mac``, when it was present at the last refresh."""
        return self._by_mac.get(mac)

    def lookup(self, ip: str) -> str | None:
        """Return the MAC that owns ``ip``, or ``None`` when it is not known."""
        address = _parse(ip)
        if address is None:
            return None
        return self._by_ip.get(str(address))

    def is_internal(self, ip: str) -> bool:
        """Whether ``ip`` is on this LAN (RFC 1918, ULA, or an explicit prefix)."""
        address = _parse(ip)
        if address is None:
            return False
        if any(address in prefix for prefix in self._lan_prefixes):
            return True
        networks = _PRIVATE_V4 if address.version == 4 else _PRIVATE_V6
        return any(address in network for network in networks)

    def is_external(self, ip: str) -> bool:
        """Whether ``ip`` is a usable peer outside the LAN."""
        address = _parse(ip)
        if address is None or self.is_internal(ip):
            return False
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            return False
        return not (address.version == 4 and address == _BROADCAST_V4)

    def is_ipv6(self, ip: str) -> bool:
        """Whether ``ip`` is a valid IPv6 address."""
        address = _parse(ip)
        return address is not None and address.version == 6


def _parse(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None
