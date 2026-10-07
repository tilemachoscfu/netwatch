import sqlite3
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_inventory import AT, OBS, result

from netwatch.database.store import Store
from netwatch.models.records import timestamp
from netwatch.services.inventory import Inventory
from netwatch.utils.config import Config
from netwatch.web.app import create_app


def test_schema_one_database_is_preserved_by_dashboard(tmp_path: Path) -> None:
    config = Config(database_path=tmp_path / "existing.db")
    with Store(config.database_path) as store:
        Inventory(store, 300).record(result(OBS), at=AT)
        Inventory(store, 300).edit("1", name="Existing NAS", trusted=True, set_name=True)
        store.heartbeat(timestamp(AT), successful=True)
        counts = [
            store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("devices", "observations", "events", "scans")
        ]
    app = create_app(config, secret_key="test-key")
    client = app.test_client()
    assert client.get("/api/device/1").json["device"]["name"] == "Existing NAS"
    with Store(config.database_path) as store:
        assert store.connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert counts == [
            store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("devices", "observations", "events", "scans")
        ]
        assert store.monitor_status()["running"] == 1


def test_database_failure_returns_safe_service_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = Config(database_path=tmp_path / "db.sqlite")
    app = create_app(config, secret_key="test-key")
    monkeypatch.setattr(
        "netwatch.web.app.Store", Mock(side_effect=sqlite3.OperationalError("secret"))
    )
    response = app.test_client().get("/api/devices")
    assert response.status_code == 503 and "secret" not in response.get_data(as_text=True)
