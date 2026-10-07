from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


def timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Timestamps must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class Observation:
    ip: str
    mac: str
    hostname: str | None = None
    vendor: str | None = None
    source: str = "neighbor"


@dataclass(frozen=True)
class Device:
    id: int
    ip: str
    mac: str
    hostname: str | None
    vendor: str | None
    first_seen: str
    last_seen: str
    online: bool
    trusted: bool
    name: str | None
    notes: str
    trust_state: str = "UNKNOWN"


@dataclass(frozen=True)
class Event:
    id: int
    device_id: int
    kind: str
    occurred_at: str
    details: dict[str, Any]


@dataclass(frozen=True)
class DiscoveryResult:
    observations: tuple[Observation, ...]
    subnet: str
    interface: str
    complete: bool
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanReport:
    scan_id: int
    observed: int
    events: tuple[Event, ...] = ()
    new_devices: tuple[Device, ...] = ()
    complete: bool = True
    errors: tuple[str, ...] = field(default_factory=tuple)
