import ipaddress
import json
from dataclasses import dataclass
from typing import Any

from netwatch.utils.config import Config
from netwatch.utils.process import DiscoveryError, run_command
from netwatch.utils.validation import private_network, valid_interface


@dataclass(frozen=True)
class Lan:
    network: ipaddress.IPv4Network
    interface: str


def parse_interfaces(payload: str) -> list[Lan]:
    try:
        entries = json.loads(payload)
        if not isinstance(entries, list):
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise DiscoveryError("Malformed interface information") from exc
    candidates: list[Lan] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        flags = entry.get("flags", [])
        if not isinstance(flags, list) or "UP" not in flags:
            continue
        name = entry.get("ifname")
        if not valid_interface(name) or name == "lo":
            continue
        addresses = entry.get("addr_info", [])
        if not isinstance(addresses, list):
            continue
        for address in addresses:
            if not isinstance(address, dict) or address.get("family") != "inet":
                continue
            try:
                interface = ipaddress.IPv4Interface(f"{address['local']}/{address['prefixlen']}")
                network = private_network(str(interface.network))
            except (KeyError, ValueError, TypeError):
                continue
            candidate = Lan(network, name)
            if candidate not in candidates:
                candidates.append(candidate)
    return candidates


def _default_interfaces(payload: str) -> set[str]:
    try:
        routes: Any = json.loads(payload)
        if not isinstance(routes, list):
            raise ValueError
        valid = [
            route
            for route in routes
            if isinstance(route, dict) and isinstance(route.get("dev"), str)
        ]
        if not valid:
            return set()
        best_metric = min(int(route.get("metric", 0)) for route in valid)
        return {route["dev"] for route in valid if int(route.get("metric", 0)) == best_metric}
    except (TypeError, ValueError) as exc:
        raise DiscoveryError("Malformed default route information") from exc


def detect_lan(config: Config) -> Lan:
    candidates = parse_interfaces(run_command(["ip", "-j", "-4", "address", "show"]))
    if config.interface:
        candidates = [lan for lan in candidates if lan.interface == config.interface]
    if config.subnet:
        configured = private_network(config.subnet)
        candidates = [lan for lan in candidates if configured.subnet_of(lan.network)]
        # More than one interface attached to a target is ambiguous even with an explicit subnet.
        candidates = list(dict.fromkeys(Lan(configured, lan.interface) for lan in candidates))
    elif not config.interface and len(candidates) > 1:
        defaults = _default_interfaces(run_command(["ip", "-j", "-4", "route", "show", "default"]))
        preferred = [lan for lan in candidates if lan.interface in defaults]
        if preferred:
            candidates = preferred
    if not candidates:
        raise DiscoveryError("No connected RFC1918 LAN matches the configuration")
    if len(candidates) != 1:
        raise DiscoveryError("Multiple LANs found; configure subnet and interface explicitly")
    lan = candidates[0]
    if (
        any(method in config.discovery_methods for method in ("ping", "nmap"))
        and lan.network.num_addresses - 2 > config.max_hosts
    ):
        raise DiscoveryError(
            "Active discovery subnet exceeds max_hosts; configure a smaller subnet"
        )
    return lan
