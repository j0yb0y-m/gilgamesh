"""Map EVE addresses to inventory devices and classify LAN versus external."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

from gilgamesh.behaviour.attribution import DeviceMap
from gilgamesh.devices import DeviceRecord

NOW = datetime(2026, 11, 1, 2, 0, tzinfo=UTC)


def device(mac: str, *ips: str) -> DeviceRecord:
    return DeviceRecord(mac=mac, ips=ips, first_ts=NOW, last_ts=NOW)


def test_refresh_maps_every_inventory_ip_to_its_mac() -> None:
    devices = [device("aa:bb:cc:dd:ee:01", "10.0.0.20", "192.168.1.20")]

    device_map = DeviceMap()
    device_map.refresh(devices)

    assert device_map.lookup("10.0.0.20") == "aa:bb:cc:dd:ee:01"
    assert device_map.lookup("192.168.1.20") == "aa:bb:cc:dd:ee:01"


def test_cgnat_is_external_but_link_local_is_special() -> None:
    device_map = DeviceMap()

    assert device_map.is_external("100.64.0.10") is True
    assert device_map.is_external("169.254.1.1") is False
    assert device_map.is_internal("192.168.1.10") is True
    assert device_map.is_internal("fd00::1") is True


def test_duplicate_ip_keeps_the_most_recent_device() -> None:
    devices = [
        device("aa:bb:cc:dd:ee:01", "10.0.0.20"),
        device("aa:bb:cc:dd:ee:02", "10.0.0.20"),
    ]

    device_map = DeviceMap()
    device_map.refresh(devices)

    assert device_map.lookup("10.0.0.20") == "aa:bb:cc:dd:ee:01"


def test_explicit_lan_prefixes_override_the_defaults() -> None:
    device_map = DeviceMap(lan_prefixes=[ipaddress.ip_network("203.0.113.0/24")])

    assert device_map.is_internal("203.0.113.9") is True
    assert device_map.is_external("203.0.113.9") is False


def test_invalid_ip_lookup_and_classification_are_false() -> None:
    device_map = DeviceMap()

    assert device_map.lookup("not-an-ip") is None
    assert device_map.is_internal("not-an-ip") is False
    assert device_map.is_external("not-an-ip") is False
    assert device_map.is_ipv6("not-an-ip") is False


def test_ipv6_is_normalized_before_lookup() -> None:
    device_map = DeviceMap()
    device_map.refresh([device("aa:bb:cc:dd:ee:03", "2001:0db8::1")])

    assert device_map.lookup("2001:db8::1") == "aa:bb:cc:dd:ee:03"
    assert device_map.is_ipv6("2001:db8::1") is True


def test_map_is_bounded() -> None:
    devices = [
        device("aa:bb:cc:dd:ee:01", "10.0.0.1"),
        device("aa:bb:cc:dd:ee:02", "10.0.0.2"),
    ]

    device_map = DeviceMap(max_entries=1)
    device_map.refresh(devices)

    assert device_map.lookup("10.0.0.1") == "aa:bb:cc:dd:ee:01"
    assert device_map.lookup("10.0.0.2") is None


def test_special_addresses_are_neither_internal_nor_external() -> None:
    device_map = DeviceMap()

    for address in (
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "255.255.255.255",
        "0.0.0.0",  # noqa: S104 - test literal, not a bind address
    ):
        assert device_map.is_internal(address) is False, address
        assert device_map.is_external(address) is False, address

    for address in ("::1", "fe80::1", "ff02::1", "::"):
        assert device_map.is_internal(address) is False, address
        assert device_map.is_external(address) is False, address


def test_public_and_documentation_addresses_are_external() -> None:
    device_map = DeviceMap()

    for address in ("8.8.8.8", "203.0.113.9", "2001:4860:4860::8888"):
        assert device_map.is_external(address) is True, address
        assert device_map.is_internal(address) is False, address


def test_refresh_replaces_the_previous_map() -> None:
    device_map = DeviceMap()
    device_map.refresh([device("aa:bb:cc:dd:ee:01", "10.0.0.1")])
    device_map.refresh([device("aa:bb:cc:dd:ee:02", "10.0.0.2")])

    assert device_map.lookup("10.0.0.1") is None
    assert device_map.lookup("10.0.0.2") == "aa:bb:cc:dd:ee:02"
