import ipaddress
import re

PRIVATE_LANS = tuple(
    ipaddress.IPv4Network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def valid_interface(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:\-]{0,14}", value) is not None
    )


def private_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError(
            "Subnet must be a canonical IPv4 CIDR (for example 192.168.1.0/24)"
        ) from exc
    if not isinstance(network, ipaddress.IPv4Network) or not any(
        network.subnet_of(lan) for lan in PRIVATE_LANS
    ):
        raise ValueError("Only RFC1918 private IPv4 LAN subnets are allowed")
    if network.prefixlen > 30:
        raise ValueError("Subnet must contain usable LAN hosts (/30 or larger)")
    return network


def normalize_mac(value: str) -> str:
    compact = value.replace(":", "").replace("-", "").lower()
    if not re.fullmatch(r"[0-9a-f]{12}", compact):
        raise ValueError("Invalid MAC address")
    if compact == "000000000000" or int(compact[:2], 16) & 1:
        raise ValueError("MAC address must be a nonzero unicast address")
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2))


def host_in_network(value: str, network: ipaddress.IPv4Network) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return ip in network and ip not in (network.network_address, network.broadcast_address)
