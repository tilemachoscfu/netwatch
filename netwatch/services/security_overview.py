"""Read-only security presentation over existing inventory and event evidence."""

from datetime import UTC, datetime, timedelta
from typing import Any

from netwatch.database.store import Store
from netwatch.models.records import Event, timestamp, utc_now
from netwatch.notifications.security import security_alerts
from netwatch.services.monitor import check_health
from netwatch.utils.config import Config

WINDOWS = {"24h": 1, "7d": 7, "30d": 30}
STATES = ("TRUSTED", "KNOWN", "UNKNOWN", "BLOCKED")
EVENT_KINDS = (
    "new_device",
    "blocked_device_online",
    "trusted_mac_changed",
    "mac_at_ip_changed",
    "hostname_changed",
    "vendor_changed",
    "device_online",
)
DESCRIPTIONS = {
    "new_device": ("MEDIUM", "New device", "A new MAC identity was first observed on the LAN."),
    "blocked_device_online": (
        "HIGH",
        "Blocked device online",
        "A device flagged BLOCKED was observed online.",
    ),
    "trusted_mac_changed": (
        "HIGH",
        "Trusted MAC mismatch",
        "Different MAC evidence was observed for a trusted identity.",
    ),
    "known_identity_changed": (
        "MEDIUM",
        "Identity changed",
        "Both hostname and vendor changed; review the identity.",
    ),
    "long_absence_return": (
        "MEDIUM",
        "Returned after long absence",
        "A device returned after the configured long absence.",
    ),
}


def _date(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


def _age(value: str, at: datetime) -> str:
    seen = _date(value)
    if seen is None or seen > at:
        return "Unknown"
    minutes = int((at - seen).total_seconds() // 60)
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h {minutes % 60}m"
    return f"{hours // 24}d {hours % 24}h"


class SecurityOverview:
    def __init__(self, store: Store, config: Config, *, at: datetime | None = None) -> None:
        self.store = store
        self.config = config
        self.at = (at or utc_now()).astimezone(UTC)
        self.devices = {device.id: device for device in store.devices()}

    def events(self, window: str = "24h", device_id: int | None = None) -> list[dict[str, Any]]:
        if window not in WINDOWS:
            raise ValueError("Security window must be 24h, 7d, or 30d")
        since = timestamp(self.at - timedelta(days=WINDOWS[window]))
        until = timestamp(self.at)
        raw = tuple(self.store.events_between(since, until, EVENT_KINDS))
        # Reuse monitoring's conservative interpretation, without instantiating
        # NotificationService or a provider, claiming events, or writing to SQLite.
        derived = security_alerts(self.store, raw, self.config.notifications.long_absence)
        evidence = {
            (event.id, event.kind): event
            for event in raw
            if event.kind in ("new_device", "blocked_device_online", "trusted_mac_changed")
        }
        for alert in derived:
            evidence[(alert.event_id, alert.kind)] = Event(
                alert.event_id, alert.device.id, alert.kind, alert.occurred_at, alert.details
            )
        for event in self.store.recorded_security_events(since, until):
            evidence[(event.id, event.kind)] = event
        values = []
        revisions = {id: self.store.trust_revision(id) for id in self.devices}
        for event in evidence.values():
            if device_id is not None and event.device_id != device_id:
                continue
            device = self.devices[event.device_id]
            severity, title, description = DESCRIPTIONS[event.kind]
            identity = self.store.observation_identity(device.id, event.occurred_at)
            pending = revisions[device.id] <= event.id
            if event.kind == "new_device":
                pending = device.trust_state == "UNKNOWN"
            elif event.kind == "blocked_device_online":
                pending = pending and device.trust_state == "BLOCKED" and device.online
            elif event.kind == "trusted_mac_changed":
                pending = pending and device.trust_state == "TRUSTED"
            elif event.kind == "known_identity_changed":
                pending = pending and device.trust_state in ("KNOWN", "TRUSTED")
            else:
                pending = pending and device.trust_state != "BLOCKED"
            values.append(
                {
                    "id": event.id,
                    "device_id": device.id,
                    "occurred_at": event.occurred_at,
                    "severity": severity,
                    "name": device.name or device.hostname or f"Unknown device #{device.id}",
                    "ip": identity["ip"] if identity else device.ip,
                    "mac": identity["mac"] if identity else device.mac,
                    "kind": event.kind,
                    "title": title,
                    "description": description,
                    "review_state": device.trust_state,
                    "requires_review": pending,
                }
            )
        return sorted(values, key=lambda row: (_date(row["occurred_at"]), row["id"]), reverse=True)

    def summary(self) -> dict[str, Any]:
        events = self.events()
        blocked = [
            device
            for device in self.devices.values()
            if device.trust_state == "BLOCKED" and device.online
        ]
        new_unknown = [
            device
            for device in self.devices.values()
            if device.trust_state == "UNKNOWN" and self._new(device.first_seen)
        ]
        pending_unknown = [
            device for device in self.devices.values() if device.trust_state == "UNKNOWN"
        ]
        high = [
            event for event in events if event["requires_review"] and event["severity"] == "HIGH"
        ]
        medium = [
            event
            for event in events
            if event["requires_review"]
            and event["severity"] == "MEDIUM"
            and event["kind"] != "new_device"
        ]
        healthy = check_health(self.store, self.config, at=self.at)
        reasons = []
        if blocked:
            reasons.append(f"{len(blocked)} BLOCKED device(s) currently online.")
        if high:
            reasons.append(f"{len(high)} high-priority security event(s) need review.")
        if pending_unknown:
            reasons.append(f"{len(pending_unknown)} UNKNOWN device(s) awaiting manual review.")
        if new_unknown:
            reasons.append(f"{len(new_unknown)} new UNKNOWN device(s) in the last 24 hours.")
        if medium:
            reasons.append(f"{len(medium)} security event(s) need review.")
        if not healthy:
            reasons.append("Monitor stopped, starting, or stale; observations may be outdated.")
        status = "ALERT" if blocked or high else "ATTENTION" if reasons else "SECURE"
        counts = {
            state.lower(): sum(d.trust_state == state for d in self.devices.values())
            for state in STATES
        }
        return {
            **counts,
            "total": len(self.devices),
            "online": sum(device.online for device in self.devices.values()),
            "offline": sum(not device.online for device in self.devices.values()),
            "status": status,
            "reasons": reasons or ["No new unknown or blocked activity requiring attention."],
            "new_devices_24h": sum(self._new(d.first_seen) for d in self.devices.values()),
            "security_events_24h": len(events),
            "last_successful_scan": self.store.latest_successful_scan(),
            "monitor_healthy": healthy,
        }

    def _new(self, value: str) -> bool:
        seen = _date(value)
        return seen is not None and timedelta(0) <= self.at - seen <= timedelta(days=1)

    def overview(self, window: str = "24h", *, include_offline: bool = False) -> dict[str, Any]:
        events = self.events(window)
        unknown = []
        for device in self.devices.values():
            if device.trust_state == "UNKNOWN":
                unknown.append(
                    {
                        "id": device.id,
                        "name": device.name,
                        "hostname": device.hostname,
                        "ip": device.ip,
                        "mac": device.mac,
                        "vendor": device.vendor,
                        "online": device.online,
                        "trust_state": device.trust_state,
                        "first_seen": device.first_seen,
                        "last_seen": device.last_seen,
                        "display_name": device.name
                        or device.hostname
                        or f"Unknown device #{device.id}",
                        "known_for": _age(device.first_seen, self.at),
                        "new_unknown": self._new(device.first_seen),
                    }
                )
        gateway_ip = self.store.network_context().get("gateway")
        gateway = next((d for d in self.devices.values() if d.ip == gateway_ip), None)
        groups = [
            {
                "state": state,
                "devices": [
                    {
                        "id": d.id,
                        "name": d.name or d.hostname or f"Device #{d.id}",
                        "ip": d.ip,
                        "online": d.online,
                    }
                    for d in self.devices.values()
                    if d.trust_state == state
                    and (include_offline or d.online)
                    and (gateway is None or d.id != gateway.id)
                ],
            }
            for state in STATES
        ]
        return {
            **self.summary(),
            "window": window,
            "events": events[:100],
            "event_count": len(events),
            "unknown_devices": unknown,
            "include_offline": include_offline,
            "map": {
                "gateway": {
                    "id": gateway.id,
                    "name": gateway.name or gateway.hostname or "Gateway",
                    "ip": gateway.ip,
                    "online": gateway.online,
                }
                if gateway
                else None,
                "gateway_ip": gateway_ip,
                "groups": groups,
            },
        }
