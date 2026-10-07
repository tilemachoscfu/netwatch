"""Conservative security policy over committed inventory events; no discovery here."""

import hashlib
import json
from collections import defaultdict
from typing import Any

from netwatch.database.store import Store
from netwatch.models.records import Event
from netwatch.notifications.alerts import Alert


def security_alerts(store: Store, events: tuple[Event, ...], long_absence: float) -> list[Alert]:
    alerts = []
    identities: dict[tuple[int, str], dict[str, Event]] = defaultdict(dict)
    titles = {
        "new_device": ("HIGH", "⚠️ NEW DEVICE"),
        "blocked_device_online": ("HIGH", "🚨 BLOCKED DEVICE ONLINE"),
        "trusted_mac_changed": ("HIGH", "🚨 TRUSTED MAC MISMATCH — REVIEW CANDIDATE"),
        "known_identity_changed": ("MEDIUM", "⚠️ DEVICE IDENTITY CHANGED"),
        "long_absence_return": ("MEDIUM", "⚠️ DEVICE RETURNED AFTER LONG ABSENCE"),
    }

    def add(event: Event, kind: str, details: dict[str, Any] | None = None) -> None:
        priority, title = titles[kind]
        alerts.append(
            Alert(
                event.id,
                kind,
                title,
                store.device(str(event.device_id)),
                event.occurred_at,
                details or event.details,
                priority,
            )
        )

    for event in events:
        device = store.device(str(event.device_id))
        if (
            (event.kind == "new_device" and device.trust_state == "UNKNOWN")
            or (event.kind == "blocked_device_online" and device.trust_state == "BLOCKED")
            or (event.kind == "trusted_mac_changed" and device.trust_state == "TRUSTED")
        ):
            add(event, event.kind)
        elif (
            event.kind == "mac_at_ip_changed"
            and device.trust_state == "TRUSTED"
            and event.details.get("old_mac") == device.mac
            and event.details.get("ip") == store.network_context().get("gateway")
        ):
            add(
                event,
                "trusted_mac_changed",
                {
                    **event.details,
                    "candidate_only": True,
                    "evidence": "Current kernel gateway address; different MAC observed",
                },
            )
        elif event.kind == "device_online" and device.trust_state != "BLOCKED":
            absence = event.details.get("absence_seconds", 0)
            if isinstance(absence, (int, float)) and absence >= long_absence:
                add(event, "long_absence_return")
        elif (
            event.kind in ("hostname_changed", "vendor_changed")
            and device.trust_state
            in (
                "KNOWN",
                "TRUSTED",
            )
            and event.details.get("source") != "local_identification"
        ):
            old, new = event.details.get("old"), event.details.get("new")
            if (
                isinstance(old, str)
                and isinstance(new, str)
                and old.strip()
                and new.strip()
                and old.casefold().rstrip(".") != new.casefold().rstrip(".")
            ):
                identities[(device.id, event.occurred_at)][event.kind] = event
    for changes in identities.values():
        if len(changes) == 2:
            add(
                changes["hostname_changed"],
                "known_identity_changed",
                {kind: event.details for kind, event in changes.items()},
            )
    return alerts


def state_key(store: Store, alert: Alert) -> str:
    """Ignore DHCP IP, timestamps and absence duration; compare security evidence."""
    details = alert.details
    material = {
        "trust": alert.device.trust_state,
        "mac": alert.device.mac,
        "old_mac": details.get("old_mac"),
        "new_mac": details.get("new_mac"),
    }
    if alert.kind == "known_identity_changed":
        material["identity"] = {
            key: {"old": value.get("old"), "new": value.get("new")}
            for key, value in details.items()
            if isinstance(value, dict)
        }
    if alert.kind == "blocked_device_online":
        material["review_revision"] = store.trust_revision(alert.device.id)
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
