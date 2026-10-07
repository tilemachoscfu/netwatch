"""Mobile templates use existing data and safe links without changing inventory."""

from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from test_inventory import AT, OBS, result

from netwatch.database.store import Store
from netwatch.models.records import timestamp
from netwatch.services.inventory import Inventory
from netwatch.utils.config import Config
from netwatch.web.app import create_app


class Elements(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def matching(self, tag: str, **attrs: Any) -> list[dict[str, str | None]]:
        return [
            values
            for kind, values in self.tags
            if kind == tag
            and all(key in values and values[key] == value for key, value in attrs.items())
        ]


@pytest.fixture
def mobile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for module in ("security_overview", "dashboard", "inventory", "monitor"):
        monkeypatch.setattr(f"netwatch.services.{module}.utc_now", lambda: AT)
    config = Config(database_path=tmp_path / "mobile.db")
    app = create_app(config, secret_key="isolated-mobile-fixture")
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.record(
            result(OBS, replace(OBS, mac="00:11:22:33:44:66", ip="192.168.203.3")), at=AT
        )
        inventory.edit("1", name="Fixture Router", set_name=True, trust_state="TRUSTED")
        store.save_network_context({"gateway": OBS.ip, "observed_at": timestamp(AT)})
        store.heartbeat(timestamp(AT), successful=True)
    return config, app.test_client()


@pytest.mark.parametrize("path", ["/", "/devices", "/unknown", "/events", "/device/1"])
def test_navigation_and_safe_area_viewport_render_on_every_view(mobile, path: str) -> None:
    _, client = mobile
    response = client.get(path)
    assert response.status_code == 200
    tags = Elements(response.get_data(as_text=True))
    viewport = tags.matching("meta", name="viewport")[0]["content"]
    assert viewport and "viewport-fit=cover" in viewport
    assert "user-scalable=no" not in viewport
    assert tags.matching("nav", **{"aria-label": "Mobile navigation"})
    selected = tags.matching("a", **{"aria-current": "page"})
    assert len(selected) == 1
    assert selected[0]["href"] == ("/devices" if path.startswith("/device/") else path)
    assert tags.matching("a", href="/unknown")
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_native_group_disclosures_keep_recorded_gateway_and_safe_device_links(mobile) -> None:
    _, client = mobile
    html = client.get("/").get_data(as_text=True)
    tags = Elements(html)
    groups = [
        attrs
        for kind, attrs in tags.tags
        if kind == "details" and attrs.get("class") == "map-group"
    ]
    assert {g["data-disclosure-key"] for g in groups} == {
        "map-TRUSTED",
        "map-KNOWN",
        "map-UNKNOWN",
        "map-BLOCKED",
    }
    assert all("open" in group and "data-responsive-details" in group for group in groups)
    assert tags.matching("a", href="/device/1", **{"class": "map-gateway"})
    assert "Fixture Router" in html and "not physical connections" in html
    assert tags.matching("details", **{"class": "status-explanation mobile-only"})
    assert tags.matching("ul", **{"data-compact-reasons": None})


def test_inventory_cards_preserve_desktop_columns_and_exact_timestamps(mobile) -> None:
    _, client = mobile
    html = client.get("/devices").get_data(as_text=True)
    tags = Elements(html)
    labels = {attrs["data-label"] for kind, attrs in tags.tags if kind == "td"}
    assert labels >= {"IP", "MAC", "Hostname", "Vendor", "Category", "Trust", "Last seen (UTC)"}
    times = [attrs for kind, attrs in tags.tags if kind == "time" and "data-relative-time" in attrs]
    assert times and all(t["datetime"] == timestamp(AT) and "UTC" in t["title"] for t in times)
    assert tags.matching("details", **{"class": "filters-disclosure panel"})
    assert timestamp(AT).encode() in client.get("/device/1").data


def test_active_inventory_filters_stay_accessible_on_mobile(mobile) -> None:
    _, client = mobile
    html = client.get("/devices?q=Fixture").get_data(as_text=True)
    details = Elements(html).matching("details", **{"class": "filters-disclosure panel"})
    assert "data-keep-open" in details[0]
    html = client.get("/unknown").get_data(as_text=True)
    details = Elements(html).matching("details", **{"class": "filters-disclosure panel"})
    assert "data-keep-open" not in details[0]


def test_mobile_page_reads_preserve_policy_inventory_and_history(mobile) -> None:
    config, client = mobile
    before = client.get("/api/security").json
    with Store(config.database_path) as store:
        devices, events = store.devices(), store.events()
        observations = store.observations(1)
    for path in ("/", "/devices", "/unknown", "/device/1", "/events"):
        assert client.get(path).status_code == 200
    assert client.get("/api/security").json == before
    with Store(config.database_path) as store:
        assert store.devices() == devices and store.events() == events
        assert store.observations(1) == observations
        assert (
            store.connection.execute("SELECT COUNT(*) FROM notification_claims").fetchone()[0] == 0
        )
