"""Passive-first investigation with an optional, single-packet reachability check."""

import json
import re
import sqlite3
import time
from collections import Counter
from datetime import datetime
from difflib import SequenceMatcher
from typing import Any

from netwatch.database.store import Store
from netwatch.models.records import timestamp, utc_now
from netwatch.services.fingerprints import local_dhcp
from netwatch.utils.config import Config
from netwatch.utils.process import DiscoveryError, run_command
from netwatch.utils.validation import host_in_network, normalize_mac, private_network

TIMEOUT = 5.0
COOLDOWN = 60
RULES = {
    "Phone": r"\b(iphone|smartphone|phone|pixel)\b",
    "Computer": r"\b(computer|desktop|laptop|macbook|workstation|thinkpad)\b",
    "Server": r"\b(server|nas|synology|truenas|proxmox)\b",
    "Smart TV": r"\b(smart\s?tv|bravia|webos|television)\b",
    "Streaming device": r"\b(chromecast|google\s?cast|appletv|apple\s?tv|roku|firetv)\b",
    "Camera": r"\b(camera|ipcam)\b",
    "Doorbell": r"\b(doorbell)\b",
    "Air conditioner": r"\b(aircon|air\s?conditioner)\b",
    "Smart appliance": r"\b(dishwasher|washing\s?machine|fridge)\b",
    "IoT device": r"\b(thermostat|smartplug|sensor|iot)\b",
    "Network infrastructure": r"\b(router|gateway|switch|access\s?point)\b",
}


class InvestigationBusy(ValueError):
    pass


def age_seconds(value: str, at: datetime) -> float:
    try:
        return max(0, (at - datetime.fromisoformat(value)).total_seconds())
    except (ValueError, TypeError):
        return float("inf")


def latest(store: Store, device_id: int) -> dict[str, Any] | None:
    runs = store.investigations(device_id)
    if not runs:
        return None
    run = runs[0]
    if run["status"] == "Investigating" and age_seconds(run["investigated_at"], utc_now()) > 15:
        # A killed web worker cannot leave the UI stuck after a restart.
        run["status"] = "Failed"
        run["result"] = {"error": "Investigation interrupted; retry to collect current evidence."}
    return run


def label(value: str | None) -> str:
    return (value or "")[:253].casefold().removesuffix(".local").replace("_", "-")


class InvestigationService:
    def __init__(self, store: Store, config: Config) -> None:
        self.store = store
        self.config = config

    def run(self, device_id: int, *, active: bool = False) -> dict[str, Any]:
        # Validate ID via the same database resolver before binding it to SQLite.
        device = self.store.device(str(device_id))
        at = utc_now()
        with self.store.transaction():
            device = self.store.device(str(device.id))
            if device.trust_state != "UNKNOWN":
                raise ValueError("Only UNKNOWN devices can be investigated")
            previous = self.store.investigations(device.id)
            if previous and age_seconds(previous[0]["investigated_at"], at) < COOLDOWN:
                raise InvestigationBusy("Wait 60 seconds between investigations of this device")
            run_id = self.store.start_investigation(device.id, timestamp(at))
        deadline = time.monotonic() + TIMEOUT
        self.store.connection.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
        status = "Complete"
        try:
            # A coherent snapshot does not hold a write lock while gathering evidence.
            self.store.connection.execute("BEGIN")
            result = self.collect(device.id, at)
            if active:
                self.reachability(device.id, result, at, deadline)
            # Bound persisted JSON even for large Unicode metadata. Original
            # observations remain in inventory; never duplicate unbounded payloads.
            if len(json.dumps(result, ensure_ascii=True)) > 60000:
                result["missing_evidence"].append("Evidence display abbreviated to storage budget.")
                while len(json.dumps(result, ensure_ascii=True)) > 60000:
                    for key in ("evidence", "reasons", "possible_matches"):
                        if result[key]:
                            result[key].pop()
                            break
            if time.monotonic() >= deadline:
                raise TimeoutError
        except (TimeoutError, sqlite3.OperationalError, OSError, ValueError):
            status = "Failed"
            result = {"error": "Evidence collection unavailable or timed out; retry later."}
        finally:
            self.store.connection.set_progress_handler(None, 0)
            self.store.connection.rollback()
        with self.store.transaction():
            if self.store.device(str(device.id)).trust_state != "UNKNOWN":
                status = "Failed"
                result = {"error": "Device was manually reviewed during investigation."}
            self.store.finish_investigation(run_id, status, result)
        return {
            "id": run_id,
            "device_id": device.id,
            "investigated_at": timestamp(at),
            "status": status,
            "result": result,
        }

    def reachability(
        self, device_id: int, result: dict[str, Any], at: datetime, deadline: float
    ) -> None:
        """One ICMP echo to a fresh DB-resolved LAN IP; no ports or authentication."""
        if result["confidence"] not in ("LOW", "INSUFFICIENT"):
            result["active_discovery"] = "Not performed: passive evidence is sufficient for review."
            return
        device = self.store.device(str(device_id))
        try:
            normalize_mac(device.mac)
            if (
                device.trust_state != "UNKNOWN"
                or not device.online
                or age_seconds(device.last_seen, at) > min(300, self.config.offline_timeout)
                or self.config.subnet is None
                or not host_in_network(device.ip, private_network(self.config.subnet))
            ):
                raise ValueError
        except ValueError:
            result["active_discovery"] = (
                "Not performed: selected device needs a fresh observation, valid unicast MAC "
                "and address in the configured private LAN."
            )
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        arguments = ["ping", "-n", "-c", "1", "-W", "1"]
        if self.config.interface:
            arguments.extend(["-I", self.config.interface])
        arguments.extend(["--", device.ip])
        try:
            run_command(arguments, timeout=min(2.0, remaining))
            observation = (
                "One ICMP echo received a reply; reachability does not establish identity."
            )
        except DiscoveryError:
            observation = (
                "No reachability confirmation: no reply, tool unavailable or check timed out. "
                "This does not establish that the device is offline."
            )
        result["evidence"].append(
            {
                "source": "bounded ICMP reachability",
                "observation": observation,
                "timestamp": timestamp(utc_now()),
                "reliability": "LOW",
                "mode": "active",
            }
        )
        result["mode"] = "passive + active"
        result["active_discovery"] = (
            "One selected-device ICMP echo attempted; at most two seconds. "
            "Identity confidence unchanged. No ports, services or credentials probed."
        )

    def collect(self, device_id: int, at: datetime) -> dict[str, Any]:
        device = self.store.device(str(device_id))
        evidence: list[dict[str, str]] = []
        conflicts: list[str] = []
        reasons: list[str] = []
        missing = [
            "No stored mDNS, SSDP, model, Home Assistant or router service evidence available.",
            "Vendor/OUI identifies an interface manufacturer, not a product or owner.",
        ]

        def add(source: str, observation: str, when: str, reliability: str = "LOW") -> None:
            evidence.append(
                {
                    "source": source,
                    "observation": observation[:300],
                    "timestamp": when[:80],
                    "reliability": reliability,
                    "mode": "passive",
                }
            )

        valid_mac = True
        private_mac = False
        try:
            mac = normalize_mac(device.mac)
            private_mac = bool(int(mac[:2], 16) & 2)
        except ValueError:
            valid_mac = False
            conflicts.append("Malformed MAC: vendor and interface identity cannot be validated.")
        if private_mac:
            conflicts.append(
                "Locally administered MAC: may be private/randomized or manually assigned; "
                "OUI attribution and continuity are uncertain."
            )
        add(
            "inventory",
            f"MAC {device.mac}; IP {device.ip}; interface {self.store.interface_for(device.id)}",
            device.last_seen,
            "MEDIUM",
        )
        if device.vendor:
            add("stored vendor/OUI", device.vendor, device.last_seen)
        if device.name:
            add("administrator label", device.name, timestamp(at))
        if device.notes:
            add(
                "administrator notes",
                "Existing notes available in Identity; manually review them.",
                timestamp(at),
            )
        add(
            "inventory times",
            f"First seen {device.first_seen}; last seen {device.last_seen}; "
            f"recorded {'online' if device.online else 'offline'}",
            device.last_seen,
            "MEDIUM",
        )

        count = self.store.connection.execute(
            "SELECT COUNT(*) FROM observations WHERE device_id = ?", (device.id,)
        ).fetchone()[0]
        observations = self.store.observations(device.id, 500)
        names = self.store.connection.execute(
            "SELECT hostname, MAX(observed_at) AS at, COUNT(*) AS n FROM observations "
            "WHERE device_id = ? AND hostname IS NOT NULL AND hostname != '' "
            "GROUP BY hostname ORDER BY MAX(id) DESC LIMIT 20",
            (device.id,),
        ).fetchall()
        candidates: dict[str, set[str]] = {}
        repeated_categories: set[str] = set()

        def hint(name: str, source: str, *, repeated: bool = False) -> None:
            text = name[:253].casefold().replace("-", " ").replace("_", " ")
            for category, rule in RULES.items():
                if re.search(rule, text):
                    candidates.setdefault(category, set()).add(source)
                    if repeated:
                        repeated_categories.add(category)
                    reasons.append(f"{source}: reported name {name[:253]} suggests {category}.")

        for row in names:
            add("hostname history", f"{row['hostname']} ({row['n']} observations)", row["at"])
            hint(row["hostname"], "hostname history", repeated=row["n"] >= 2)
        if device.hostname:
            hint(device.hostname, "current hostname")
            add("current hostname", device.hostname, device.last_seen)
        if device.name:
            hint(device.name, "administrator label")
        leases = local_dhcp(self.config.dhcp_files, at=at)
        dhcp_name = leases.get((device.mac, device.ip)) if valid_mac else None
        if dhcp_name:
            add("local DHCP lease", dhcp_name, timestamp(at), "MEDIUM")
            hint(dhcp_name, "local DHCP lease")
        else:
            missing.append("No matching unexpired local DHCP name available.")
        for row in self.store.connection.execute(
            "SELECT ip, MAX(observed_at) AS at FROM observations WHERE device_id = ? "
            "GROUP BY ip ORDER BY MAX(id) DESC LIMIT 20",
            (device.id,),
        ):
            add("IP history", row["ip"], row["at"], "MEDIUM")
        vendors = self.store.connection.execute(
            "SELECT vendor, MAX(observed_at) AS at FROM observations WHERE device_id = ? "
            "AND vendor IS NOT NULL GROUP BY vendor ORDER BY MAX(id) DESC LIMIT 8",
            (device.id,),
        ).fetchall()
        if len(vendors) > 1:
            conflicts.append(
                "Stored vendor attributions changed; manufacturer evidence is uncertain."
            )
        for row in vendors:
            add("vendor history", row["vendor"], row["at"])
        for source in sorted({row["source"] for row in observations})[:10]:
            add("observation source", source, device.last_seen, "MEDIUM")
        events = self.store.events(device.id, 100)
        changes = Counter(
            event.kind
            for event in events
            if event.kind
            in (
                "ip_changed",
                "hostname_changed",
                "vendor_changed",
                "device_online",
                "device_offline",
            )
        )
        if changes:
            add(
                "recent event history",
                "; ".join(f"{key}: {n}" for key, n in changes.items()),
                events[0].occurred_at,
                "MEDIUM",
            )
        context = self.store.network_context()
        if (
            context.get("gateway") == device.ip
            and device.online
            and age_seconds(device.last_seen, at) <= self.config.offline_timeout
            and age_seconds(context.get("observed_at", ""), at) < 600
        ):
            candidates.setdefault("Network infrastructure", set()).add("stored local default route")
            reasons.append("Fresh stored local default route matches this observed IP.")
            add(
                "stored local default route",
                "IP is the recorded LAN gateway",
                context["observed_at"],
                "MEDIUM",
            )
        if len(candidates) > 1:
            conflicts.append(
                "Reported names/topology suggest conflicting device categories: "
                + ", ".join(sorted(candidates))
            )
        category = next(iter(candidates)) if len(candidates) == 1 else "Unknown"
        # These sources are self-reported hints. Repetition is not independent proof.
        # HIGH is reserved for future direct, independently validated model evidence.
        confidence = "LOW" if candidates else "INSUFFICIENT"
        if (
            category != "Unknown"
            and not conflicts
            and (
                category in repeated_categories
                or "local DHCP lease" in candidates[category]
                or "stored local default route" in candidates[category]
            )
        ):
            confidence = "MEDIUM"
        identity = (
            f"Possible {category.lower()}" if category != "Unknown" else "Insufficient evidence"
        )
        if not reasons:
            reasons.append(
                "No product/category evidence; vendor alone cannot identify this device."
            )
        presence = self.presence(
            device.last_seen, device.first_seen, count, observations, at, changes
        )
        matches = self.matches(device, [row["hostname"] for row in names], valid_mac, private_mac)
        action = (
            f"Confirm the reported {category.lower()} name against devices you own. "
            if category != "Unknown"
            else "Compare the MAC and historical names with labels or device settings you own. "
        )
        if matches:
            action += (
                "Review the possible existing-device matches; do not merge without confirmation. "
            )
        action += "Use the manual review form only after confirming identity."
        return {
            "device_id": device.id,
            "investigated_at": timestamp(at),
            "mode": "passive",
            "mac": device.mac[:253],
            "ip": device.ip[:253],
            "vendor": (device.vendor or "")[:253],
            "hostname": (device.hostname or "")[:253],
            "possible_identity": identity,
            "category": category,
            "confidence": confidence,
            "reasons": reasons[:30],
            "conflicting_evidence": conflicts,
            "missing_evidence": missing,
            "evidence": evidence,
            "presence_pattern": presence,
            "possible_matches": matches,
            "recommended_action": action,
            "observation_count": count,
            "sample_size": len(observations),
            "rules_version": 1,
            "active_discovery": "Not performed; investigation reads local evidence only.",
        }

    def presence(self, last_seen, first_seen, count, observations, at, changes) -> str:
        age = age_seconds(last_seen, at)
        if count == 0:
            return "No observations recorded; presence pattern is unknown."
        ago = (
            f"approximately {int(age / 3600)} hours ago"
            if age != float("inf")
            else "at an unknown time"
        )
        if count == 1:
            return f"Seen once {ago}; insufficient observations for a behavioral inference."
        if age > 7 * 86400:
            return f"Historical/stale: {count} observations; last seen {ago}."
        pattern = (
            "Intermittent observations"
            if changes.get("device_offline")
            else "Repeated observations"
        )
        if age_seconds(first_seen, at) < 86400:
            pattern = "Recently appeared; " + pattern.lower()
        return (
            f"{pattern}: {count} total; sampled {len(observations)} most recent observations "
            f"from {observations[-1]['observed_at']} to {observations[0]['observed_at']}. "
            "Neighbour/cache sightings do not prove continuous uptime or usage periods."
        )

    def matches(self, device, names, valid_mac, private_mac) -> list[dict[str, Any]]:
        matches = []
        labels = {label(name) for name in [*names, device.hostname] if name}
        labels -= {"unknown", "localhost", "android", "iphone", "device"}
        for row in self.store.connection.execute(
            "SELECT id, name, hostname, vendor, ip, mac, last_seen FROM devices "
            "WHERE trust_state IN ('KNOWN','TRUSTED') ORDER BY id LIMIT 500"
        ):
            reasons = []
            exact = label(row["hostname"]) in labels
            similarity = any(
                len(name) >= 8
                and len(label(row["hostname"])) >= 8
                and SequenceMatcher(None, name, label(row["hostname"])).ratio() >= 0.85
                for name in labels
            )
            if exact or similarity:
                reasons.append(
                    "Matching reported hostname" if exact else "Similar reported hostname"
                )
            if row["ip"] == device.ip:
                reasons.append("Same recorded IP; address reuse/stale records are possible")
            if not reasons:
                continue
            if valid_mac and not private_mac and device.vendor and device.vendor == row["vendor"]:
                reasons.append("Same stored interface vendor; not model proof")
            kinds = [
                "duplicate identity or alternate interface",
                "stale historical record/IP reuse",
            ]
            if private_mac:
                kinds.append("private/randomized MAC possible")
            matches.append(
                {
                    "device_id": row["id"],
                    "name": (row["name"] or row["hostname"] or f"Device {row['id']}")[:253],
                    "confidence": "MEDIUM" if exact else "LOW",
                    "reasons": reasons,
                    "possibilities": kinds,
                }
            )
        return sorted(matches, key=lambda match: match["confidence"] != "MEDIUM")[:5]
