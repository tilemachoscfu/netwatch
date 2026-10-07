import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from netwatch.database.store import Store
from netwatch.models.records import Device, timestamp, utc_now
from netwatch.utils.config import Config
from netwatch.utils.process import DiscoveryError, run_command
from netwatch.utils.validation import host_in_network, normalize_mac, private_network

logger = logging.getLogger(__name__)
CATEGORIES = (
    "Computer",
    "Mobile Device",
    "Tablet",
    "Smart TV",
    "IoT",
    "Network Equipment",
    "Printer",
    "Server",
    "Unknown",
)
RULES = {
    "Computer": r"\b(computer|desktop|laptop|macbook|workstation)\b",
    "Mobile Device": r"\b(iphone|smartphone|phone|pixel)\b",
    "Tablet": r"\b(ipad|tablet)\b",
    "Smart TV": r"\b(smart[ -]?tv|appletv|bravia|roku|firetv)\b",
    "IoT": r"\b(thermostat|doorbell|smartplug|sensor|aircon|camera)\b",
    "Network Equipment": r"\b(router|gateway|switch|access[ -]?point)\b",
    "Printer": r"\b(printer|laserjet|officejet|deskjet)\b",
    "Server": r"\b(server|nas|synology|truenas|proxmox)\b",
}


def parse_dhcp(payload: str, *, at: datetime) -> dict[tuple[str, str], str]:
    """Read dnsmasq leases only; matching MAC+IP and an unexpired lease are required."""
    leases = {}
    conflicts: set[tuple[str, str]] = set()
    for line in payload.splitlines():
        columns = line.split()
        if len(columns) < 4 or columns[3] == "*":
            continue
        try:
            expiry = int(columns[0])
            mac = normalize_mac(columns[1])
        except ValueError:
            continue
        if expiry != 0 and expiry <= at.timestamp():
            continue
        hostname = columns[3]
        if len(hostname) <= 253 and re.fullmatch(r"[A-Za-z0-9_.-]+", hostname):
            key = (mac, columns[2])
            if key in leases and leases[key] != hostname:
                conflicts.add(key)
            leases[key] = hostname
    for key in conflicts:
        leases.pop(key, None)
    return leases


def local_dhcp(paths: tuple[Path, ...], *, at: datetime) -> dict[tuple[str, str], str]:
    leases = {}
    conflicts: set[tuple[str, str]] = set()
    for path in paths[:8]:
        try:
            # This is passive, optional local data, never fetched from a router.
            if not path.is_file() or path.stat().st_size > 1048576:
                continue
            with path.open(encoding="utf-8") as file:
                for key, hostname in parse_dhcp(file.read(1048577), at=at).items():
                    if key in leases and leases[key] != hostname:
                        conflicts.add(key)
                    leases[key] = hostname
        except (OSError, UnicodeError):
            logger.debug("Optional local DHCP evidence unavailable")
    for key in conflicts:
        leases.pop(key, None)
    return leases


def topology(config: Config) -> dict[str, Any]:
    if config.interface is None or config.subnet is None:
        return {}
    network = private_network(config.subnet)
    try:
        addresses = json.loads(
            run_command(["ip", "-j", "-4", "addr", "show", "dev", config.interface])
        )
        routes = json.loads(run_command(["ip", "-j", "-4", "route", "show", "default"]))
        local_ips = [
            entry.get("local")
            for device in addresses
            if isinstance(device, dict)
            for entry in device.get("addr_info", [])
            if isinstance(entry, dict) and host_in_network(entry.get("local", ""), network)
        ]
        gateways = {
            route.get("gateway")
            for route in routes
            if isinstance(route, dict)
            and route.get("dev") == config.interface
            and host_in_network(route.get("gateway", ""), network)
        }
        if not local_ips:
            # User services can start before the LAN acquires its address. This
            # is unavailable evidence, not a new topology with an absent gateway.
            return {}
        return {
            "interface": config.interface,
            "subnet": config.subnet,
            "local_ip": local_ips[0] if len(local_ips) == 1 else None,
            "gateway": next(iter(gateways)) if len(gateways) == 1 else None,
            "observed_at": timestamp(utc_now()),
        }
    except (DiscoveryError, ValueError, TypeError, AttributeError):
        logger.debug("Local topology information unavailable")
        return {}


def fingerprint(
    device: Device,
    *,
    previous_ips: list[str],
    source: str | None = None,
    dhcp_hostname: str | None = None,
    gateway: str | None = None,
) -> dict[str, Any]:
    evidence: list[dict[str, str]] = []
    candidates: set[str] = set()
    for kind, value in (
        ("assigned_name", device.name),
        ("observed_hostname", device.hostname),
        ("local_dhcp_hostname", dhcp_hostname),
        ("inventory_vendor", device.vendor),
        ("neighbour_identity", f"{device.ip} / {device.mac}"),
        ("observation_source", source),
        ("historical_ips", ", ".join(previous_ips) or None),
    ):
        if value is None:
            continue
        evidence.append({"source": kind, "value": value})
        if kind in ("assigned_name", "observed_hostname", "local_dhcp_hostname"):
            text = value.lower().replace("_", " ").replace("-", " ")
            for category, rule in RULES.items():
                if re.search(rule, text):
                    candidates.add(category)
                    evidence.append(
                        {"source": "category_rule", "value": f"{kind} supports {category}"}
                    )
    if gateway and device.ip == gateway:
        candidates.add("Network Equipment")
        evidence.append({"source": "kernel_default_route", "value": "Current LAN gateway"})
    category = next(iter(candidates)) if len(candidates) == 1 else "Unknown"
    confidence = "medium" if category != "Unknown" else "unknown"
    if category == "Network Equipment" and gateway == device.ip:
        confidence = "high"
    if category in ("Mobile Device", "Tablet", "Computer", "Smart TV"):
        labels = " ".join([device.hostname or "", device.name or "", dhcp_hostname or ""]).lower()
        if "apple" in (device.vendor or "").lower() and any(
            term in labels for term in ("iphone", "ipad", "macbook", "appletv")
        ):
            confidence = "high"
            evidence.append(
                {"source": "corroboration", "value": "Reported Apple name and Apple OUI agree"}
            )
    if len(candidates) > 1:
        evidence.append(
            {"source": "conflict", "value": "Conflicting category hints; identity needs review"}
        )
    if category == "Unknown" and len(candidates) <= 1:
        evidence.append(
            {
                "source": "assessment",
                "value": "Insufficient category evidence; vendor alone is inconclusive",
            }
        )
    return {"category": category, "confidence": confidence, "evidence": evidence}


class FingerprintService:
    def __init__(self, store: Store, config: Config) -> None:
        self.store = store
        self.config = config

    def refresh(self, *, collect_topology: bool = False) -> None:
        at = utc_now()
        leases = local_dhcp(self.config.dhcp_files, at=at)
        context = topology(self.config) if collect_topology else self.store.network_context()
        with self.store.transaction():
            if context:
                self.store.save_network_context(context)
            for device in self.store.devices():
                observations = self.store.observations(device.id, 1)
                value = fingerprint(
                    device,
                    previous_ips=self.store.previous_ips(device),
                    source=observations[0]["source"] if observations else None,
                    dhcp_hostname=leases.get((device.mac, device.ip)),
                    gateway=context.get("gateway"),
                )
                old = self.store.fingerprint(device.id)
                if old is None or any(old[key] != value[key] for key in value):
                    self.store.save_fingerprint(device.id, value, timestamp(at))
