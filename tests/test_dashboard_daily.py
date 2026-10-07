from dataclasses import replace
from pathlib import Path

import pytest
from test_inventory import OBS, result

from netwatch.database.store import Store
from netwatch.models.records import Observation, utc_now
from netwatch.services.inventory import Inventory
from netwatch.utils.config import Config
from netwatch.web.app import create_app


@pytest.fixture
def client(tmp_path: Path):
    config = Config(database_path=tmp_path / "db.sqlite")
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.record(
            result(
                replace(OBS, ip="192.168.203.10", hostname="Macbook", vendor="Apple"),
                Observation("192.168.203.2", "00:11:22:33:44:66", hostname="printer"),
                Observation("192.168.203.30", "00:11:22:33:44:77", hostname="NAS"),
            ),
            at=utc_now(),
        )
        inventory.edit("3", trusted=True, name="Office NAS", set_name=True)
        store.set_offline(2)
    return create_app(config, secret_key="test-key").test_client()


@pytest.mark.parametrize(
    "query,ids",
    [
        ("status=online", [1, 3]),
        ("status=offline", [2]),
        ("trust=trusted", [3]),
        ("trust=unknown", [1, 2]),
        ("q=office", [3]),
        ("q=apple", [1]),
        ("category=Printer", [2]),
        ("status=offline&trust=trusted", []),
        ("sort=ip", [2, 1, 3]),
        ("sort=ip&order=desc", [3, 1, 2]),
        ("sort=name", [1, 3, 2]),
        ("sort=id&order=desc", [3, 2, 1]),
    ],
)
def test_search_filters_and_numerical_ip_sort(client, query: str, ids: list[int]) -> None:
    values = client.get("/api/devices?" + query).json["devices"]
    assert [value["id"] for value in values] == ids


@pytest.mark.parametrize(
    "query",
    [
        "sort=id;DROP TABLE devices",
        "status=invalid",
        "category=Phone",
        "order=sideways",
        "trust=yes",
        "q=" + "a" * 201,
    ],
)
def test_invalid_filters_are_rejected(client, query: str) -> None:
    assert client.get("/api/devices?" + query).status_code == 400
    assert len(client.get("/api/devices").json["devices"]) == 3


def test_summary_live_fields_real_alerts_new_highlight_and_categories(client) -> None:
    summary = client.get("/api/summary").json
    assert summary["last_scan"]["complete"] == 1
    assert len(summary["recent_alerts"]) == 3
    assert all(event["kind"] == "new_device" for event in summary["recent_alerts"])
    assert summary["recent_events"] and not summary["monitor_healthy"]
    values = client.get("/api/devices").json["devices"]
    assert values[0]["new_unknown"] and not values[2]["new_unknown"]
    assert values[0]["category"] == "Computer"
    html = client.get("/").data
    for text in (
        b"Recent alerts",
        b"Recent network events",
        b"Last scan:",
        b"Network overview",
        b"Gateway",
        b"Search devices",
        b"NEW",
    ):
        assert text in html
    assert b"Fingerprint evidence" in client.get("/device/1").data


def test_metadata_edit_refreshes_persisted_category(client) -> None:
    csrf = client.get("/api/csrf").json["csrf_token"]
    value = client.patch("/api/device/1", json={"name": "Printer"}, headers={"X-CSRF-Token": csrf})
    # A user name that contradicts the observed hostname is retained as a conflict.
    assert value.status_code == 200 and value.json["fingerprint"]["category"] == "Unknown"
    assert any(item["source"] == "conflict" for item in value.json["fingerprint"]["evidence"])
    assert not value.json["device"]["trusted"]
