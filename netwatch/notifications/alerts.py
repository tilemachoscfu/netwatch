import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol, TextIO

from netwatch.database.store import Store
from netwatch.models.records import Device, Event, timestamp, utc_now
from netwatch.notifications.console import clean_text, notify_new_device

logger = logging.getLogger(__name__)
TITLES = {
    "new_device": "NEW DEVICE DETECTED / UNKNOWN DEVICE",
    "device_offline": "DEVICE OFFLINE",
    "device_online": "DEVICE ONLINE AGAIN",
    "ip_changed": "IP ADDRESS CHANGED",
}


@dataclass(frozen=True)
class Alert:
    event_id: int
    kind: str
    title: str
    device: Device
    occurred_at: str
    details: dict[str, Any]
    priority: str = "INFO"


class NotificationProvider(Protocol):
    def send(self, alert: Alert) -> None: ...


class ConsoleProvider:
    def __init__(self, stream: TextIO) -> None:
        self.stream = stream

    def send(self, alert: Alert) -> None:
        if alert.kind == "new_device":
            notify_new_device(alert.device, self.stream)
            print("TRUST: UNKNOWN DEVICE", file=self.stream)
        else:
            print(
                f"{alert.title} | "
                f"{clean_text(alert.device.name or alert.device.hostname or 'UNKNOWN')}"
                f" | IP: {alert.device.ip} | MAC: {alert.device.mac} | TIME: {alert.occurred_at}",
                file=self.stream,
            )
            if alert.kind == "ip_changed":
                print(
                    f"IP: {clean_text(alert.details['old'])} -> {clean_text(alert.details['new'])}",
                    file=self.stream,
                )
        self.stream.flush()


class NotificationService:
    """Deliver only transition events; unchanged observations never generate alerts."""

    def __init__(
        self,
        store: Store,
        providers: tuple[NotificationProvider, ...],
        *,
        cooldown_seconds: float = 3600,
        long_absence_seconds: float = 86400,
    ) -> None:
        self.store = store
        self.providers = providers
        self.cooldown_seconds = max(3600, cooldown_seconds)
        self.long_absence_seconds = long_absence_seconds

    def dispatch(self, events: tuple[Event, ...]) -> None:
        for event in events:
            if event.kind not in TITLES:
                continue
            alert = Alert(
                event.id,
                event.kind,
                TITLES[event.kind],
                self.store.device(str(event.device_id)),
                event.occurred_at,
                event.details,
            )
            for provider in self.providers:
                if getattr(provider, "security_only", False) is True:
                    continue
                try:
                    provider.send(alert)
                except Exception:
                    # Provider failures must not undo committed inventory or stop monitoring.
                    logger.warning("Notification delivery failed for event %d", event.id)
        # Local console remains an operational timeline. External Telegram alerts
        # use a narrower security policy and persistent deduplication.
        from netwatch.notifications.security import security_alerts, state_key

        external = [p for p in self.providers if getattr(p, "security_only", False) is True]
        if not external:
            return
        for alert in security_alerts(self.store, events, self.long_absence_seconds):
            for provider in external:
                try:
                    now = utc_now()
                    claimed = self.store.claim_notification(
                        provider=getattr(provider, "provider_key", type(provider).__name__),
                        event_id=alert.event_id,
                        kind=alert.kind,
                        device_id=alert.device.id,
                        state_key=state_key(self.store, alert),
                        at=timestamp(now),
                        cutoff=timestamp(now - timedelta(seconds=self.cooldown_seconds)),
                        details={**alert.details, "priority": alert.priority},
                    )
                    if claimed:
                        provider.send(alert)
                except Exception:
                    logger.warning("Security notification failed for event %d", alert.event_id)

    def close(self) -> None:
        for provider in self.providers:
            close = getattr(provider, "close", None)
            if close is not None:
                try:
                    close()
                except Exception:
                    logger.warning("Notification provider shutdown failed")

    def flush(self) -> None:
        for provider in self.providers:
            flush = getattr(provider, "flush", None)
            if flush is not None:
                try:
                    flush()
                except Exception:
                    logger.warning("Notification provider flush failed")
