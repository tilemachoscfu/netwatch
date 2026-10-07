import logging
import subprocess
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import replace
from pathlib import Path

from netwatch.discovery.enrichment import VendorLookup, resolve_hostname
from netwatch.discovery.network import Lan, detect_lan
from netwatch.discovery.parsers import parse_arp, parse_neighbors, parse_nmap
from netwatch.models.records import DiscoveryResult, Observation
from netwatch.utils.config import Config
from netwatch.utils.process import DiscoveryError, run_command

logger = logging.getLogger(__name__)


def ping_host(ip: str, interface: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", "1", "-I", interface, ip],
            capture_output=True,
            timeout=3,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiscoveryError("ping unavailable or timed out") from exc
    if result.returncode not in (0, 1):
        raise DiscoveryError("ping failed; check permissions and interface")
    return result.returncode == 0


def ping_sweep(lan: Lan, workers: int) -> set[str]:
    pending: dict[Future[bool], str] = {}
    reachable: set[str] = set()

    def collect(completed: set[Future[bool]]) -> None:
        for future in completed:
            ip = pending.pop(future)
            if future.result():
                reachable.add(ip)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        try:
            for ip in lan.network.hosts():
                # Bound queued work and notice tool/permission failures promptly.
                if len(pending) >= workers:
                    completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                    collect(completed)
                pending[pool.submit(ping_host, str(ip), lan.interface)] = str(ip)
                # A global ceiling of ten probe starts per second, including responsive LANs.
                time.sleep(0.1)
                collect({future for future in pending if future.done()})
            collect(set(pending))
        finally:
            for future in pending:
                future.cancel()
    return reachable


def read_neighbors(lan: Lan, reachable: set[str] | None) -> list[Observation]:
    try:
        payload = run_command(["ip", "-j", "-4", "neigh", "show", "dev", lan.interface])
        return parse_neighbors(
            payload, lan.network, lan.interface, reachable, interface_scoped=True
        )
    except DiscoveryError:
        # ARP cache entries lack age information: only use the fallback after an active probe.
        if reachable is None:
            raise
        try:
            payload = Path("/proc/net/arp").read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise DiscoveryError("Cannot read neighbour or ARP table") from exc
        return parse_arp(payload, lan.network, lan.interface, reachable)


class Scanner:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.vendors = VendorLookup(config.vendor_file)
        self.hostname_offset = 0

    def discover(self) -> DiscoveryResult:
        # Resolve each time: DHCP/interface changes must never retain a stale scan scope.
        lan = detect_lan(self.config)
        observations: list[Observation] = []
        errors: list[str] = []
        reachable: set[str] | None = None
        if "ping" in self.config.discovery_methods:
            try:
                reachable = ping_sweep(lan, self.config.ping_workers)
            except DiscoveryError as exc:
                errors.append(str(exc))
        if "nmap" in self.config.discovery_methods:
            try:
                payload = run_command(
                    [
                        "nmap",
                        "-sn",
                        "-n",
                        "-e",
                        lan.interface,
                        "--max-rate",
                        "10",
                        "--max-retries",
                        "1",
                        "--host-timeout",
                        "5s",
                        "-oX",
                        "-",
                        str(lan.network),
                    ],
                    timeout=max(30, (lan.network.num_addresses - 2) / 10 + 30),
                )
                found, active = parse_nmap(payload, lan.network)
                observations.extend(found)
                reachable = (reachable or set()) | active
            except DiscoveryError as exc:
                errors.append(str(exc))
        # All active methods need neighbour-table MAC correlation, even if neighbor is omitted.
        try:
            observations.extend(read_neighbors(lan, reachable))
        except DiscoveryError as exc:
            errors.append(str(exc))
        merged: dict[str, Observation] = {}
        for observation in observations:
            previous = merged.get(observation.mac)
            if previous is not None and previous.ip != observation.ip:
                logger.warning("MAC %s has multiple observed IPs; retaining one", observation.mac)
            if previous is not None and previous.ip == observation.ip:
                observation = replace(observation, vendor=observation.vendor or previous.vendor)
            merged[observation.mac] = observation
        hostnames: dict[str, str | None] = {}
        candidates = list(merged.values())
        if self.config.resolve_hostnames and candidates:
            deadline = time.monotonic() + 10
            # Rotate enrichment order so slow DNS does not starve later devices forever.
            offset = self.hostname_offset % len(candidates)
            for observation in candidates[offset:] + candidates[:offset]:
                if time.monotonic() >= deadline:
                    logger.debug("Hostname enrichment budget exhausted")
                    break
                hostnames[observation.mac] = resolve_hostname(observation.ip)
                self.hostname_offset += 1
        enriched = []
        for observation in candidates:
            vendor = observation.vendor or self.vendors.lookup(observation.mac)
            hostname = hostnames.get(observation.mac)
            enriched.append(replace(observation, vendor=vendor, hostname=hostname))
        for error in errors:
            logger.warning("Discovery degraded: %s", error)
        return DiscoveryResult(
            tuple(enriched), str(lan.network), lan.interface, not errors, tuple(errors)
        )
