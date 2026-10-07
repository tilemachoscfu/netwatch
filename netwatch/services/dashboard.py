from dataclasses import asdict
from datetime import datetime
from ipaddress import IPv4Address
from typing import Any

from netwatch.database.store import Store
from netwatch.models.records import utc_now
from netwatch.services.fingerprints import CATEGORIES, fingerprint
from netwatch.services.investigation import latest
from netwatch.services.monitor import check_health
from netwatch.services.security_overview import SecurityOverview
from netwatch.utils.config import Config


class DashboardQueries:
    """Read inventory and existing histories; discovery remains in the monitor."""

    def __init__(self, store: Store, config: Config) -> None:
        self.store = store
        self.config = config

    def summary(self) -> dict[str, Any]:
        devices = self.store.devices()
        return {
            "online": sum(device.online for device in devices),
            "offline": sum(not device.online for device in devices),
            "unknown": sum(device.trust_state == "UNKNOWN" for device in devices),
            "trusted": sum(device.trust_state == "TRUSTED" for device in devices),
            "known": sum(device.trust_state == "KNOWN" for device in devices),
            "blocked": sum(device.trust_state == "BLOCKED" for device in devices),
            "total": len(devices),
            "monitor_healthy": check_health(self.store, self.config),
            "monitor": self.store.monitor_status(),
            "last_scan": self.store.latest_scan(),
            "recent_alerts": [asdict(event) for event in self.store.recent_alerts()],
            "recent_events": [asdict(event) for event in self.store.events(limit=10)],
            "network": self.store.network_context(),
            "security": SecurityOverview(self.store, self.config).summary(),
        }

    def devices(
        self,
        *,
        query: str = "",
        status: str = "all",
        trust: str = "all",
        category: str = "all",
        sort: str = "id",
        order: str = "asc",
    ) -> list[dict[str, Any]]:
        sorts = {"id", "ip", "name", "vendor", "last_seen", "first_seen", "category"}
        if (
            len(query) > 200
            or status not in ("all", "online", "offline")
            or trust not in ("all", "trusted", "known", "unknown", "blocked")
            or category not in ("all", *CATEGORIES)
            or sort not in sorts
            or order not in ("asc", "desc")
        ):
            raise ValueError("Invalid inventory search, filter, or sort")
        values = []
        for device in self.store.devices():
            value = asdict(device)
            value["fingerprint"] = self.store.fingerprint(device.id) or fingerprint(
                device, previous_ips=self.store.previous_ips(device)
            )
            value["category"] = value["fingerprint"]["category"]
            value["new_unknown"] = (
                device.trust_state == "UNKNOWN"
                and 0
                <= (utc_now() - datetime.fromisoformat(device.first_seen)).total_seconds()
                < 86400
            )
            if status != "all" and device.online != (status == "online"):
                continue
            if trust != "all" and device.trust_state != trust.upper():
                continue
            if category != "all" and value["category"] != category:
                continue
            if (
                query.casefold()
                not in " ".join(
                    str(value[key] or "")
                    for key in ("id", "name", "hostname", "ip", "mac", "vendor", "category")
                ).casefold()
            ):
                continue
            values.append(value)

        def key(value: dict[str, Any]) -> Any:
            if sort == "ip":
                return int(IPv4Address(value["ip"]))
            if sort == "id":
                return value["id"]
            if sort == "name":
                return (value["name"] or value["hostname"] or "Unknown").casefold()
            return (value[sort] or "").casefold()

        return sorted(values, key=key, reverse=order == "desc")

    def detail(self, device_id: int, limit: int = 100, window: str = "24h") -> dict[str, Any]:
        device = self.store.device(str(device_id))
        return {
            "device": asdict(device),
            "investigation": latest(self.store, device.id),
            "investigation_history": self.store.investigations(device.id),
            "observations": self.store.observations(device.id, limit),
            "events": [asdict(event) for event in self.store.events(device.id, limit)],
            "previous_ips": self.store.previous_ips(device),
            "fingerprint": self.store.fingerprint(device.id)
            or fingerprint(device, previous_ips=self.store.previous_ips(device)),
            "security_events": SecurityOverview(self.store, self.config).events(window, device_id)[
                :100
            ],
            "security_window": window,
        }
