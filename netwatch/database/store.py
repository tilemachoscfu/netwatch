from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from netwatch.models.records import Device, Event, Observation

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    mac TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL,
    hostname TEXT,
    vendor TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    online INTEGER NOT NULL CHECK (online IN (0, 1)),
    trusted INTEGER NOT NULL DEFAULT 0 CHECK (trusted IN (0, 1)),
    name TEXT,
    notes TEXT NOT NULL DEFAULT '',
    interface TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    subnet TEXT,
    interface TEXT,
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    errors TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    device_id INTEGER NOT NULL REFERENCES devices(id),
    observed_at TEXT NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    hostname TEXT,
    vendor TEXT,
    source TEXT NOT NULL,
    UNIQUE (scan_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_observations_device ON observations(device_id, id);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    kind TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id, id);
CREATE TABLE IF NOT EXISTS monitor_status (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    heartbeat TEXT NOT NULL,
    last_success TEXT,
    running INTEGER NOT NULL CHECK (running IN (0, 1))
);
PRAGMA user_version = 1;
"""

MIGRATION_2 = """
CREATE TABLE IF NOT EXISTS fingerprints (
    device_id INTEGER PRIMARY KEY REFERENCES devices(id),
    category TEXT NOT NULL,
    confidence TEXT NOT NULL,
    evidence TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    rules_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS network_context (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    data TEXT NOT NULL
);
PRAGMA user_version = 2;
"""

MIGRATION_3 = """
ALTER TABLE devices ADD COLUMN trust_state TEXT NOT NULL DEFAULT 'UNKNOWN'
    CHECK (trust_state IN ('TRUSTED','KNOWN','UNKNOWN','BLOCKED'));
UPDATE devices SET trust_state = CASE WHEN trusted = 1 THEN 'TRUSTED' ELSE 'UNKNOWN' END;
CREATE TABLE notification_claims (
    provider TEXT NOT NULL,
    event_id INTEGER NOT NULL REFERENCES events(id),
    kind TEXT NOT NULL,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    state_key TEXT NOT NULL,
    claimed_at TEXT NOT NULL,
    details TEXT NOT NULL,
    admitted INTEGER NOT NULL CHECK (admitted IN (0, 1)),
    PRIMARY KEY (provider, event_id, kind)
);
CREATE INDEX idx_notification_cooldown
    ON notification_claims(provider, device_id, kind, state_key, claimed_at);
PRAGMA user_version = 3;
"""


def _device(row: sqlite3.Row) -> Device:
    values = {key: row[key] for key in Device.__dataclass_fields__}
    values["online"] = bool(values["online"])
    values["trusted"] = bool(values["trusted"])
    return Device(**values)


def _event(row: sqlite3.Row) -> Event:
    return Event(
        row["id"], row["device_id"], row["kind"], row["occurred_at"], json.loads(row["details"])
    )


class Store:
    def __init__(self, path: Path, *, readonly: bool = False) -> None:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            parent = path.parent.stat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or parent.st_mode & 0o022
            ):
                raise ValueError(
                    "Database must be an owner-only regular file in a private writable directory"
                )
        if readonly:
            uri = path.resolve().as_uri() + "?mode=ro"
            self.connection = sqlite3.connect(uri, uri=True, timeout=10, isolation_level=None)
        else:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if path.parent.stat().st_mode & 0o022:
                raise ValueError("Database directory must not be writable by other users")
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
            self.connection = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        try:
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA busy_timeout = 10000")
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, 3) or (readonly and version != 3):
                raise ValueError("Unsupported NetWatch database schema")
            if not readonly:
                self.connection.execute("PRAGMA journal_mode = WAL")
                if version == 0:
                    self.connection.executescript("BEGIN IMMEDIATE;\n" + SCHEMA + "\nCOMMIT;")
                if version in (0, 1):
                    self.connection.executescript("BEGIN IMMEDIATE;\n" + MIGRATION_2 + "\nCOMMIT;")
                if version in (0, 1, 2):
                    self.connection.executescript("BEGIN IMMEDIATE;\n" + MIGRATION_3 + "\nCOMMIT;")
        except Exception:
            self.connection.close()
            raise

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def devices(self, *, unknown_only: bool = False, online_only: bool = False) -> list[Device]:
        rows = self.connection.execute(
            "SELECT * FROM devices WHERE (? = 0 OR trust_state = 'UNKNOWN') "
            "AND (? = 0 OR online = 1) ORDER BY id",
            (unknown_only, online_only),
        )
        return [_device(row) for row in rows]

    def by_mac(self, mac: str) -> Device | None:
        row = self.connection.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return _device(row) if row else None

    def by_ip(self, ip: str) -> list[Device]:
        return [
            _device(row)
            for row in self.connection.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
        ]

    def device(self, selector: str) -> Device:
        if selector.isascii() and selector.isdigit():
            # Keep arbitrarily large input from overflowing SQLite's integer binder.
            rows = self.connection.execute(
                "SELECT * FROM devices WHERE CAST(id AS TEXT) = ?", (selector,)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM devices WHERE mac = ? OR ip = ? OR name = ?",
                (selector.lower().replace("-", ":"), selector, selector),
            ).fetchall()
        if not rows:
            raise ValueError("Device not found")
        if len(rows) != 1:
            raise ValueError("Ambiguous device selector; use its numeric ID or MAC address")
        return _device(rows[0])

    def insert_device(self, observation: Observation, at: str, interface: str) -> Device:
        self.connection.execute(
            "INSERT INTO devices(mac, ip, hostname, vendor, first_seen, last_seen, "
            "online, interface) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (
                observation.mac,
                observation.ip,
                observation.hostname,
                observation.vendor,
                at,
                at,
                interface,
            ),
        )
        device = self.by_mac(observation.mac)
        assert device is not None
        return device

    def update_observed(
        self, device: Device, observation: Observation, at: str, interface: str
    ) -> Device:
        self.connection.execute(
            "UPDATE devices SET ip = ?, hostname = ?, vendor = ?, last_seen = ?, online = 1, "
            "interface = ? WHERE id = ?",
            (
                observation.ip,
                observation.hostname or device.hostname,
                observation.vendor or device.vendor,
                at,
                interface,
                device.id,
            ),
        )
        return self.device(str(device.id))

    def set_offline(self, device_id: int) -> None:
        self.connection.execute("UPDATE devices SET online = 0 WHERE id = ?", (device_id,))

    def interface_for(self, device_id: int) -> str:
        return self.connection.execute(
            "SELECT interface FROM devices WHERE id = ?", (device_id,)
        ).fetchone()[0]

    def add_scan(
        self,
        started_at: str,
        completed_at: str,
        subnet: str | None,
        interface: str | None,
        complete: bool,
        errors: tuple[str, ...],
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO scans(started_at, completed_at, subnet, interface, complete, errors) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (started_at, completed_at, subnet, interface, complete, json.dumps(errors)),
        )
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    def add_observation(
        self, scan_id: int, device: Device, observation: Observation, at: str
    ) -> None:
        self.connection.execute(
            "INSERT INTO observations(scan_id, device_id, observed_at, ip, mac, "
            "hostname, vendor, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                device.id,
                at,
                observation.ip,
                observation.mac,
                observation.hostname,
                observation.vendor,
                observation.source,
            ),
        )

    def add_event(self, device_id: int, kind: str, at: str, details: dict[str, Any]) -> Event:
        cursor = self.connection.execute(
            "INSERT INTO events(device_id, kind, occurred_at, details) VALUES (?, ?, ?, ?)",
            (device_id, kind, at, json.dumps(details, ensure_ascii=True)),
        )
        assert cursor.lastrowid is not None
        return Event(cursor.lastrowid, device_id, kind, at, details)

    def events(self, device_id: int | None = None, limit: int = 50) -> list[Event]:
        rows = self.connection.execute(
            "SELECT * FROM events WHERE (? IS NULL OR device_id = ?) ORDER BY id DESC LIMIT ?",
            (device_id, device_id, limit),
        )
        return [_event(row) for row in rows]

    def events_between(
        self, since: str, until: str, kinds: tuple[str, ...], device_id: int | None = None
    ) -> list[Event]:
        """Read a complete bounded window; counts must not depend on a display limit."""
        if not kinds:
            return []
        placeholders = ",".join("?" for _ in kinds)
        rows = self.connection.execute(
            "SELECT * FROM events WHERE julianday(occurred_at) >= julianday(?) "
            "AND julianday(occurred_at) <= julianday(?) "
            f"AND kind IN ({placeholders}) AND (? IS NULL OR device_id = ?) "
            "ORDER BY julianday(occurred_at) DESC, id DESC",
            (since, until, *kinds, device_id, device_id),
        )
        return [_event(row) for row in rows]

    def recorded_security_events(self, since: str, until: str) -> list[Event]:
        """Historical security evidence remains available after a device is reviewed.

        Suppressed claims still describe real events. Reading them never claims or
        sends a notification; duplicate providers/claims are deduplicated by the view.
        """
        rows = self.connection.execute(
            "SELECT e.id, c.device_id, c.kind, e.occurred_at, c.details "
            "FROM notification_claims c JOIN events e ON e.id = c.event_id "
            "WHERE julianday(e.occurred_at) >= julianday(?) "
            "AND julianday(e.occurred_at) <= julianday(?) "
            "AND c.kind IN ('known_identity_changed','long_absence_return','trusted_mac_changed')",
            (since, until),
        )
        return [_event(row) for row in rows]

    def observation_identity(self, device_id: int, at: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT ip, mac FROM observations WHERE device_id = ? "
            "AND julianday(observed_at) <= julianday(?) "
            "ORDER BY julianday(observed_at) DESC, id DESC LIMIT 1",
            (device_id, at),
        ).fetchone()
        return dict(row) if row else None

    def observations(self, device_id: int, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM observations WHERE device_id = ? ORDER BY id DESC LIMIT ?",
            (device_id, limit),
        )
        return [dict(row) for row in rows]

    def initialize_investigations(self) -> None:
        """Additive web-owned extension; schema 3 monitors remain compatible.

        No inventory/event/notification tables or schema version are changed.
        Only the web process initializes this optional extension.
        """
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS investigations ("
            "id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id), "
            "investigated_at TEXT NOT NULL, status TEXT NOT NULL "
            "CHECK(status IN ('Investigating','Complete','Failed')), "
            "result TEXT NOT NULL CHECK(length(result) <= 65536))"
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_investigations_device ON investigations(device_id, id)"
        )

    def investigations(self, device_id: int) -> list[dict[str, Any]]:
        # Older, read-only inventories need not have the web-owned extension.
        if not self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='investigations'"
        ).fetchone():
            return []
        rows = self.connection.execute(
            "SELECT * FROM investigations WHERE device_id = ? ORDER BY id DESC LIMIT 5",
            (device_id,),
        )
        return [{**dict(row), "result": json.loads(row["result"])} for row in rows]

    def start_investigation(self, device_id: int, at: str) -> int:
        cursor = self.connection.execute(
            "INSERT INTO investigations(device_id, investigated_at, status, result) "
            "VALUES (?, ?, 'Investigating', '{}')",
            (device_id, at),
        )
        self.connection.execute(
            "DELETE FROM investigations WHERE device_id = ? AND id NOT IN "
            "(SELECT id FROM investigations WHERE device_id = ? ORDER BY id DESC LIMIT 5)",
            (device_id, device_id),
        )
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    def finish_investigation(self, run_id: int, status: str, result: dict[str, Any]) -> None:
        self.connection.execute(
            "UPDATE investigations SET status = ?, result = ? WHERE id = ?",
            (status, json.dumps(result, ensure_ascii=True), run_id),
        )

    def edit(
        self,
        device_id: int,
        *,
        trusted: bool,
        name: str | None,
        notes: str,
        trust_state: str | None = None,
    ) -> Device:
        trust_state = trust_state or ("TRUSTED" if trusted else "UNKNOWN")
        if trust_state not in ("TRUSTED", "KNOWN", "UNKNOWN", "BLOCKED"):
            raise ValueError("Invalid device trust state")
        if trusted != (trust_state == "TRUSTED"):
            raise ValueError("Conflicting device trust state")
        self.connection.execute(
            "UPDATE devices SET trusted = ?, name = ?, notes = ?, trust_state = ? WHERE id = ?",
            (trusted, name, notes, trust_state, device_id),
        )
        return self.device(str(device_id))

    def heartbeat(self, at: str, *, successful: bool, running: bool = True) -> None:
        self.connection.execute(
            "INSERT INTO monitor_status(singleton, heartbeat, last_success, running) "
            "VALUES(1, ?, ?, ?) "
            "ON CONFLICT(singleton) DO UPDATE SET heartbeat = excluded.heartbeat, "
            "last_success = COALESCE(excluded.last_success, monitor_status.last_success), "
            "running = excluded.running",
            (at, at if successful else None, running),
        )

    def monitor_status(self) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM monitor_status WHERE singleton = 1").fetchone()
        return dict(row) if row else None

    def previous_ips(self, device: Device) -> list[str]:
        rows = self.connection.execute(
            "SELECT ip FROM observations WHERE device_id = ? AND ip != ? "
            "GROUP BY ip ORDER BY MAX(id) DESC",
            (device.id, device.ip),
        )
        return [row[0] for row in rows]

    def identify(self, device_id: int, hostname: str | None, vendor: str | None) -> None:
        self.connection.execute(
            "UPDATE devices SET hostname = COALESCE(?, hostname), vendor = COALESCE(?, vendor) "
            "WHERE id = ?",
            (hostname, vendor, device_id),
        )

    def fingerprint(self, device_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM fingerprints WHERE device_id = ?", (device_id,)
        ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["evidence"] = json.loads(value["evidence"])
        return value

    def save_fingerprint(self, device_id: int, value: dict[str, Any], at: str) -> None:
        self.connection.execute(
            "INSERT INTO fingerprints VALUES (?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(device_id) DO UPDATE SET category=excluded.category, "
            "confidence=excluded.confidence, evidence=excluded.evidence, "
            "updated_at=excluded.updated_at, rules_version=excluded.rules_version",
            (device_id, value["category"], value["confidence"], json.dumps(value["evidence"]), at),
        )

    def latest_scan(self) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        value = dict(row)
        value["errors"] = json.loads(value["errors"])
        return value

    def latest_successful_scan(self) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM scans WHERE complete = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["errors"] = json.loads(value["errors"])
        return value

    def recent_alerts(self, limit: int = 10) -> list[Event]:
        return [
            _event(row)
            for row in self.connection.execute(
                "SELECT id, device_id, kind, occurred_at, details FROM events WHERE kind IN "
                "('new_device','blocked_device_online','trusted_mac_changed') "
                "UNION ALL SELECT e.id, c.device_id, c.kind, e.occurred_at, c.details "
                "FROM notification_claims c JOIN events e ON e.id = c.event_id "
                "WHERE c.provider = 'telegram' AND c.admitted = 1 "
                "AND (c.kind IN ('known_identity_changed','long_absence_return') "
                "OR (c.kind = 'trusted_mac_changed' AND e.kind != 'trusted_mac_changed')) "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        ]

    def trust_revision(self, device_id: int) -> int:
        row = self.connection.execute(
            "SELECT MAX(id) FROM events WHERE device_id = ? "
            "AND kind IN ('trusted_changed','trust_state_changed')",
            (device_id,),
        ).fetchone()
        return row[0] or 0

    def blocked_review_pending(self, device_id: int) -> bool:
        revision = self.trust_revision(device_id)
        row = self.connection.execute(
            "SELECT MAX(id) FROM events WHERE device_id = ? AND kind = 'blocked_device_online'",
            (device_id,),
        ).fetchone()
        return revision > (row[0] or 0)

    def claim_notification(
        self,
        *,
        provider: str,
        event_id: int,
        kind: str,
        device_id: int,
        state_key: str,
        at: str,
        cutoff: str,
        details: dict[str, Any],
    ) -> bool:
        """Claim before enqueue; persist both event identity and identical-state cooldown."""
        with self.transaction():
            duplicate = self.connection.execute(
                "SELECT 1 FROM notification_claims WHERE provider = ? AND event_id = ? "
                "AND kind = ?",
                (provider, event_id, kind),
            ).fetchone()
            if duplicate:
                return False
            cooldown = self.connection.execute(
                "SELECT 1 FROM notification_claims WHERE provider = ? AND "
                "device_id = ? AND kind = ? AND state_key = ? "
                "AND admitted = 1 AND claimed_at > ? LIMIT 1",
                (provider, device_id, kind, state_key, cutoff),
            ).fetchone()
            self.connection.execute(
                "INSERT INTO notification_claims VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    provider,
                    event_id,
                    kind,
                    device_id,
                    state_key,
                    at,
                    json.dumps(details),
                    int(not cooldown),
                ),
            )
            return not cooldown

    def network_context(self) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT data FROM network_context WHERE singleton=1"
        ).fetchone()
        return json.loads(row[0]) if row else {}

    def save_network_context(self, value: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO network_context VALUES (1, ?) "
            "ON CONFLICT(singleton) DO UPDATE SET data=excluded.data",
            (json.dumps(value),),
        )
