from dataclasses import replace
from datetime import datetime

from netwatch.database.store import Store
from netwatch.models.records import DiscoveryResult, Event, ScanReport, timestamp, utc_now
from netwatch.utils.validation import host_in_network, normalize_mac, private_network


class Inventory:
    def __init__(self, store: Store, offline_timeout: float) -> None:
        self.store = store
        self.offline_timeout = offline_timeout

    def record(
        self,
        result: DiscoveryResult,
        *,
        at: datetime | None = None,
        started_at: datetime | None = None,
    ) -> ScanReport:
        at = at or utc_now()
        stamp = timestamp(at)
        network = private_network(result.subnet)
        observations = []
        seen_macs: set[str] = set()
        seen_ips: set[str] = set()
        for observation in result.observations:
            mac = normalize_mac(observation.mac)
            if not host_in_network(observation.ip, network):
                raise ValueError("Discovery observation outside selected LAN")
            if mac in seen_macs or observation.ip in seen_ips:
                raise ValueError("Conflicting or duplicate discovery observation")
            seen_macs.add(mac)
            seen_ips.add(observation.ip)
            observations.append(replace(observation, mac=mac))
        events: list[Event] = []
        new_devices = []
        with self.store.transaction():
            scan_id = self.store.add_scan(
                timestamp(started_at or at),
                stamp,
                result.subnet,
                result.interface,
                result.complete,
                result.errors,
            )
            for observation in observations:
                device = self.store.by_mac(observation.mac)
                is_new = device is None
                appeared_at_ip = device is None or device.ip != observation.ip
                # Compare before updating inventory: IP reuse is evidence about the address,
                # never evidence that two MAC identities are the same physical device.
                previous_occupants = [
                    previous
                    for previous in self.store.by_ip(observation.ip)
                    if previous.mac != observation.mac
                    and previous.mac not in seen_macs
                    and self.store.interface_for(previous.id) == result.interface
                ]
                if device is None:
                    device = self.store.insert_device(observation, stamp, result.interface)
                    new_devices.append(device)
                    events.append(
                        self.store.add_event(
                            device.id,
                            "new_device",
                            stamp,
                            {
                                "ip": device.ip,
                                "mac": device.mac,
                                "hostname": device.hostname,
                                "vendor": device.vendor,
                            },
                        )
                    )
                else:
                    if stamp < device.last_seen:
                        raise ValueError("Scan time precedes a device's last observation")
                    if not device.online:
                        events.append(
                            self.store.add_event(
                                device.id,
                                "device_online",
                                stamp,
                                {
                                    "ip": observation.ip,
                                    "last_seen": device.last_seen,
                                    "absence_seconds": (
                                        at - datetime.fromisoformat(device.last_seen)
                                    ).total_seconds(),
                                },
                            )
                        )
                    for field in ("ip", "hostname", "vendor"):
                        old, new = getattr(device, field), getattr(observation, field)
                        if new is not None and new != old:
                            events.append(
                                self.store.add_event(
                                    device.id, f"{field}_changed", stamp, {"old": old, "new": new}
                                )
                            )
                    if device.trust_state == "BLOCKED" and (
                        not device.online or self.store.blocked_review_pending(device.id)
                    ):
                        events.append(
                            self.store.add_event(
                                device.id, "blocked_device_online", stamp, {"ip": observation.ip}
                            )
                        )
                    device = self.store.update_observed(
                        device, observation, stamp, result.interface
                    )
                if is_new and device.hostname and device.vendor:
                    candidates = [
                        candidate
                        for candidate in self.store.devices()
                        if candidate.id != device.id
                        and candidate.hostname
                        and candidate.hostname.casefold().rstrip(".")
                        == device.hostname.casefold().rstrip(".")
                        and candidate.vendor == device.vendor
                        and self.store.interface_for(candidate.id) == result.interface
                    ]
                    if len(candidates) == 1:
                        candidate = candidates[0]
                        if candidate.trust_state == "TRUSTED" and candidate.mac not in seen_macs:
                            events.append(
                                self.store.add_event(
                                    candidate.id,
                                    "trusted_mac_changed",
                                    stamp,
                                    {
                                        "old_mac": candidate.mac,
                                        "new_mac": device.mac,
                                        "new_device_id": device.id,
                                        "ip": device.ip,
                                        "evidence": (
                                            "Unique matching hostname and vendor; "
                                            "expected MAC absent"
                                        ),
                                        "candidate_only": True,
                                    },
                                )
                            )
                for previous in previous_occupants if appeared_at_ip else ():
                    details = {
                        "ip": observation.ip,
                        "old_mac": previous.mac,
                        "new_mac": observation.mac,
                    }
                    events.append(
                        self.store.add_event(device.id, "mac_at_ip_changed", stamp, details)
                    )
                    events.append(
                        self.store.add_event(previous.id, "mac_at_ip_changed", stamp, details)
                    )
                self.store.add_observation(scan_id, device, observation, stamp)
            if result.complete:
                for device in self.store.devices(online_only=True):
                    if device.mac in seen_macs or not host_in_network(device.ip, network):
                        continue
                    if self.store.interface_for(device.id) != result.interface:
                        continue
                    age = (at - datetime.fromisoformat(device.last_seen)).total_seconds()
                    if age >= self.offline_timeout:
                        self.store.set_offline(device.id)
                        events.append(
                            self.store.add_event(
                                device.id,
                                "device_offline",
                                stamp,
                                {
                                    "last_seen": device.last_seen,
                                    "timeout_seconds": self.offline_timeout,
                                },
                            )
                        )
        return ScanReport(
            scan_id,
            len(observations),
            tuple(events),
            tuple(new_devices),
            result.complete,
            result.errors,
        )

    def edit(
        self,
        selector: str,
        *,
        trusted: bool | None = None,
        trust_state: str | None = None,
        name: str | None = None,
        notes: str | None = None,
        set_name: bool = False,
    ) -> None:
        if name is not None and len(name) > 200:
            raise ValueError("Device name exceeds 200 characters")
        if notes is not None and len(notes) > 10000:
            raise ValueError("Notes exceed 10000 characters")
        if trust_state is not None and trust_state not in (
            "TRUSTED",
            "KNOWN",
            "UNKNOWN",
            "BLOCKED",
        ):
            raise ValueError("Invalid device trust state")
        if (
            trusted is not None
            and trust_state is not None
            and trusted != (trust_state == "TRUSTED")
        ):
            raise ValueError("Conflicting device trust state")
        at = timestamp(utc_now())
        with self.store.transaction():
            device = self.store.device(selector)
            state = trust_state or (
                device.trust_state if trusted is None else ("TRUSTED" if trusted else "UNKNOWN")
            )
            changes = {
                "trusted": state == "TRUSTED",
                "name": name if set_name else device.name,
                "notes": device.notes if notes is None else notes,
            }
            for field, value in changes.items():
                old = getattr(device, field)
                if old != value:
                    self.store.add_event(
                        device.id, f"{field}_changed", at, {"old": old, "new": value}
                    )
            if state != device.trust_state and (
                trust_state is not None or changes["trusted"] == device.trusted
            ):
                self.store.add_event(
                    device.id, "trust_state_changed", at, {"old": device.trust_state, "new": state}
                )
            self.store.edit(device.id, **changes, trust_state=state)

    def identify(
        self, selector: str, *, hostname: str | None = None, vendor: str | None = None
    ) -> None:
        """Record evidence-backed enrichment without claiming a new liveness observation."""
        if hostname is not None and (not hostname or len(hostname) > 253):
            raise ValueError("Hostname must contain 1 to 253 characters")
        if vendor is not None and (not vendor or len(vendor) > 500):
            raise ValueError("Vendor must contain 1 to 500 characters")
        with self.store.transaction():
            device = self.store.device(selector)
            for field, value in (("hostname", hostname), ("vendor", vendor)):
                if value is not None and value != getattr(device, field):
                    self.store.add_event(
                        device.id,
                        f"{field}_changed",
                        timestamp(utc_now()),
                        {
                            "old": getattr(device, field),
                            "new": value,
                            "source": "local_identification",
                        },
                    )
            self.store.identify(device.id, hostname, vendor)
