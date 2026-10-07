import os
import sqlite3
from pathlib import Path

import pytest
from test_inventory import AT, OBS, result

from netwatch.database.store import Store
from netwatch.models.records import Observation
from netwatch.services.inventory import Inventory


def test_persistence_and_safe_permissions(tmp_path: Path) -> None:
    path = tmp_path / "state/netwatch.db"
    with Store(path) as store:
        Inventory(store, 300).record(result(OBS), at=AT)
        assert store.connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert store.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with Store(path) as reopened:
        assert reopened.device("1").mac == OBS.mac
        assert reopened.events(1)[0].kind == "new_device"
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(path.parent).st_mode & 0o777 == 0o700


def test_foreign_keys_and_transaction_rollback(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError), store.transaction():
        store.insert_device(OBS, AT.isoformat(), "eth0")
        store.add_event(999, "new_device", AT.isoformat(), {})
    assert not store.devices()


def test_sql_injection_and_selector_errors(store: Store) -> None:
    Inventory(store, 300).record(result(OBS), at=AT)
    for selector in ("1 OR 1=1", "' OR 1=1 --", "9" * 100):
        with pytest.raises(ValueError, match="not found"):
            store.device(selector)
    assert store.device(OBS.mac.upper()).id == 1
    assert store.device(OBS.mac.replace(":", "-")).id == 1
    assert store.device(OBS.ip).id == 1


def test_readonly_health_store_never_creates_database(tmp_path: Path) -> None:
    path = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        Store(path, readonly=True)
    assert not path.exists()


def test_unknown_schema_refused(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 999")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="schema"):
        Store(path)


def test_duplicate_names_require_stable_selector(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS, Observation("192.168.203.3", "00:11:22:33:44:66")), at=AT)
    inventory.edit("1", name="same", set_name=True)
    inventory.edit("2", name="same", set_name=True)
    with pytest.raises(ValueError, match="Ambiguous"):
        store.device("same")


def test_device_events_are_filtered_and_limited(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    inventory.edit("1", trusted=True, name="host", set_name=True)
    assert len(store.events(1, 1)) == 1
    assert store.events(1, 1)[0].kind == "name_changed"
    assert not store.events(999)
