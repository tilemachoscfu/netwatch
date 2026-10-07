import ipaddress
import json

import pytest

from netwatch.discovery.network import parse_interfaces
from netwatch.discovery.parsers import parse_arp, parse_neighbors, parse_nmap
from netwatch.utils.process import DiscoveryError
from netwatch.utils.validation import normalize_mac

LAN = ipaddress.IPv4Network("192.168.203.0/24")
MAC = "00:11:22:33:44:55"


def test_neighbor_scope_state_and_mac() -> None:
    entries = [
        {"dst": "192.168.203.2", "dev": "eth0", "lladdr": MAC.upper(), "state": ["REACHABLE"]},
        {"dst": "192.168.203.3", "dev": "eth0", "lladdr": MAC, "state": ["STALE"]},
        {"dst": "192.168.203.4", "dev": "eth1", "lladdr": MAC, "state": ["REACHABLE"]},
        {"dst": "8.8.8.8", "dev": "eth0", "lladdr": MAC, "state": ["REACHABLE"]},
        {"dst": "192.168.203.5", "dev": "eth0", "lladdr": "bad", "state": ["REACHABLE"]},
        {"dst": "192.168.203.6", "dev": "eth0", "lladdr": MAC, "state": ["PERMANENT"]},
        {"dst": "192.168.203.255", "dev": "eth0", "lladdr": MAC, "state": ["REACHABLE"]},
        {"dst": "192.168.203.7", "dev": "eth0", "state": None},
        None,
    ]
    observations = parse_neighbors(json.dumps(entries), LAN, "eth0")
    assert [(item.ip, item.mac) for item in observations] == [("192.168.203.2", MAC)]
    observations = parse_neighbors(json.dumps(entries), LAN, "eth0", {"192.168.203.3"})
    assert len(observations) == 2


def test_interface_filtered_neighbors_can_omit_dev() -> None:
    payload = json.dumps(
        [
            {"dst": "192.168.203.2", "lladdr": MAC, "state": ["REACHABLE"]},
            {"dst": "192.168.203.3", "dev": "eth1", "lladdr": MAC, "state": ["REACHABLE"]},
            {"dst": "8.8.8.8", "lladdr": MAC, "state": ["REACHABLE"]},
        ]
    )
    assert parse_neighbors(payload, LAN, "eth0") == []
    found = parse_neighbors(payload, LAN, "eth0", interface_scoped=True)
    assert len(found) == 1 and found[0].ip == "192.168.203.2"


@pytest.mark.parametrize("payload", ["not-json", "null", "{}"])
def test_malformed_neighbors(payload: str) -> None:
    with pytest.raises(DiscoveryError):
        parse_neighbors(payload, LAN, "eth0")


def test_arp_requires_confirmation_and_complete_flags() -> None:
    payload = "\n".join(
        [
            "IP address HW type Flags HW address Mask Device",
            f"192.168.203.2 0x1 0x2 {MAC} * eth0",
            f"192.168.203.3 0x1 0x0 {MAC} * eth0",
            f"8.8.8.8 0x1 0x2 {MAC} * eth0",
            f"192.168.203.4 0x1 bad {MAC} * eth0",
            "malformed line",
        ]
    )
    assert parse_arp(payload, LAN, "eth0") == []
    assert len(parse_arp(payload, LAN, "eth0", {"192.168.203.2", "192.168.203.3"})) == 1


def test_nmap_up_hosts_and_scope() -> None:
    payload = f"""<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>
      <host><status state="up"/><address addr="192.168.203.2" addrtype="ipv4"/>
      <address addr="{MAC}" addrtype="mac" vendor="Example"/></host>
      <host><status state="down"/><address addr="192.168.203.3" addrtype="ipv4"/></host>
      <host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/></host>
      <host><status state="up"/><address addr="192.168.203.4" addrtype="ipv4"/></host>
      <runstats><finished exit="success"/></runstats></nmaprun>"""
    found, reachable = parse_nmap(payload, LAN)
    assert len(found) == 1 and found[0].vendor == "Example"
    assert reachable == {"192.168.203.2", "192.168.203.4"}


@pytest.mark.parametrize("payload", ["<broken>", "<x/>", "<nmaprun/>", '<!ENTITY a "x"><nmaprun/>'])
def test_invalid_nmap(payload: str) -> None:
    with pytest.raises(DiscoveryError):
        parse_nmap(payload, LAN)


def test_parse_interfaces_ignores_bad_public_and_down_data() -> None:
    entries = [
        {
            "ifname": "eth0",
            "flags": ["UP"],
            "addr_info": [{"family": "inet", "local": "192.168.203.2", "prefixlen": 24}],
        },
        {
            "ifname": "eth1",
            "flags": [],
            "addr_info": [{"family": "inet", "local": "10.0.0.2", "prefixlen": 24}],
        },
        {
            "ifname": "eth2",
            "flags": ["UP"],
            "addr_info": [{"family": "inet", "local": "8.8.8.8", "prefixlen": 24}],
        },
        {
            "ifname": "eth3",
            "flags": ["UP"],
            "addr_info": [{"family": "inet", "local": "bad", "prefixlen": 24}],
        },
        {"ifname": "eth4", "flags": None, "addr_info": []},
        None,
    ]
    lans = parse_interfaces(json.dumps(entries))
    assert len(lans) == 1 and lans[0].network == LAN


@pytest.mark.parametrize(
    "mac", ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:11:22:33:44:55", "bad"]
)
def test_invalid_macs(mac: str) -> None:
    with pytest.raises(ValueError):
        normalize_mac(mac)
