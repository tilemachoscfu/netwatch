import ipaddress
import json
import xml.etree.ElementTree as ET

from netwatch.models.records import Observation
from netwatch.utils.process import DiscoveryError
from netwatch.utils.validation import host_in_network, normalize_mac

LIVE_STATES = frozenset({"REACHABLE"})


def _observation(
    ip: str,
    mac: str,
    network: ipaddress.IPv4Network,
    source: str,
    hostname: str | None = None,
    vendor: str | None = None,
) -> Observation | None:
    if not host_in_network(ip, network):
        return None
    try:
        mac = normalize_mac(mac)
    except (ValueError, AttributeError):
        return None
    return Observation(ip, mac, hostname or None, vendor or None, source)


def parse_neighbors(
    payload: str,
    network: ipaddress.IPv4Network,
    interface: str,
    reachable_ips: set[str] | None = None,
    *,
    interface_scoped: bool = False,
) -> list[Observation]:
    try:
        entries = json.loads(payload)
        if not isinstance(entries, list):
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise DiscoveryError("Malformed neighbour table") from exc
    observations: list[Observation] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # iproute2 can omit dev after an interface-filtered query. Only trust that
        # omission when the caller explicitly guarantees the command's scope.
        if entry.get("dev", interface if interface_scoped else None) != interface:
            continue
        states = entry.get("state", [])
        if isinstance(states, str):
            states = states.split(",")
        if not isinstance(states, list) or any(not isinstance(state, str) for state in states):
            continue
        ip = entry.get("dst", "")
        if not isinstance(ip, str):
            continue
        confirmed = reachable_ips is not None and ip in reachable_ips
        if not confirmed and not LIVE_STATES.intersection(states):
            continue
        observation = _observation(ip, entry.get("lladdr", ""), network, "neighbor")
        if observation:
            observations.append(observation)
    return observations


def parse_arp(
    payload: str,
    network: ipaddress.IPv4Network,
    interface: str,
    reachable_ips: set[str] | None = None,
) -> list[Observation]:
    # /proc/net/arp has no freshness signal. Only actively confirmed hosts are online evidence.
    observations: list[Observation] = []
    for line in payload.splitlines()[1:]:
        columns = line.split()
        if len(columns) != 6 or columns[5] != interface:
            continue
        try:
            complete = int(columns[2], 16) & 0x2
        except ValueError:
            continue
        if not complete or reachable_ips is None or columns[0] not in reachable_ips:
            continue
        observation = _observation(columns[0], columns[3], network, "arp")
        if observation:
            observations.append(observation)
    return observations


def parse_nmap(
    payload: str,
    network: ipaddress.IPv4Network,
) -> tuple[list[Observation], set[str]]:
    # Nmap's own XML includes a DOCTYPE. Reject entity declarations before stdlib parsing.
    if "<!ENTITY" in payload.upper():
        raise DiscoveryError("Unsafe nmap XML")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise DiscoveryError("Malformed nmap XML") from exc
    if root.tag != "nmaprun":
        raise DiscoveryError("Unexpected nmap XML root")
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise DiscoveryError("Incomplete nmap result")
    observations: list[Observation] = []
    reachable: set[str] = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = {node.get("addrtype"): node for node in host.findall("address")}
        ipv4 = addresses.get("ipv4")
        if ipv4 is None or not host_in_network(ipv4.get("addr", ""), network):
            continue
        ip = ipv4.get("addr", "")
        reachable.add(ip)
        mac_node = addresses.get("mac")
        if mac_node is not None:
            # -n prevents DNS traffic; hostname enrichment is independently opt-in.
            observation = _observation(
                ip, mac_node.get("addr", ""), network, "nmap", vendor=mac_node.get("vendor")
            )
            if observation:
                observations.append(observation)
    return observations, reachable
