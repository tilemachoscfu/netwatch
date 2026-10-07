import re
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from flask import Flask
from flask.testing import FlaskClient
from test_inventory import AT, OBS, result

from netwatch.database.store import Store
from netwatch.services.inventory import Inventory
from netwatch.utils.config import Config
from netwatch.web.app import create_app


@pytest.fixture
def app(tmp_path: Path) -> Flask:
    config = Config(database_path=tmp_path / "web.db")
    app = create_app(config, secret_key="test-key-not-for-production")
    app.config.update(TESTING=True)
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.record(result(OBS), at=AT)
        inventory.record(result(replace(OBS, ip="192.168.203.3")), at=AT)
        inventory.record(result(replace(OBS, ip="192.168.203.4")), at=AT)
    return app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


@pytest.mark.parametrize("path", ["/", "/devices", "/unknown", "/events", "/device/1"])
def test_dashboard_views_render(client: FlaskClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert b"NETWATCH" in response.data
    assert b"Content" not in response.data[:20]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_home_counts_and_indicators(client: FlaskClient) -> None:
    response = client.get("/")
    for text in (
        b"Devices Online",
        b"Devices Offline",
        b"Unknown Devices",
        b"Trusted Devices",
        b"ONLINE",
        b"UNKNOWN",
        b"MONITOR STOPPED OR STALE",
    ):
        assert text in response.data
    summary = client.get("/api/summary").json
    assert summary["online"] == 1 and summary["unknown"] == 1
    assert summary["offline"] == summary["trusted"] == 0


def test_detail_identity_and_all_previous_ips(client: FlaskClient) -> None:
    detail = client.get("/api/device/1").json
    assert detail["device"]["ip"] == "192.168.203.4"
    assert detail["previous_ips"] == ["192.168.203.3", "192.168.203.2"]
    assert len(detail["observations"]) == 3
    html = client.get("/device/1").data
    for text in (b"Observation history", b"Event timeline", b"Previous IP addresses", b"Notes"):
        assert text in html


def token(client: FlaskClient) -> str:
    return client.get("/api/csrf").json["csrf_token"]


def test_api_updates_use_existing_service_and_preserve_history(client: FlaskClient) -> None:
    csrf = token(client)
    response = client.patch(
        "/api/device/1",
        json={"name": "NAS", "notes": "office", "trusted": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    detail = response.json
    assert detail["device"]["name"] == "NAS" and detail["device"]["trusted"]
    assert detail["device"]["notes"] == "office"
    assert len(detail["observations"]) == 3
    assert {event["kind"] for event in detail["events"]} >= {
        "name_changed",
        "notes_changed",
        "trusted_changed",
    }
    assert client.get("/api/devices?unknown=true").json["devices"] == []
    client.patch(
        "/api/device/1", json={"trusted": False, "name": None}, headers={"X-CSRF-Token": csrf}
    )
    assert len(client.get("/api/devices?unknown=true").json["devices"]) == 1


def test_form_update_and_html_escaping(client: FlaskClient) -> None:
    html = client.get("/device/1").get_data(as_text=True)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html)[1]
    response = client.post(
        "/device/1",
        data={
            "csrf_token": csrf,
            "name": "<script>alert(1)</script>",
            "notes": "<img src=x onerror=alert(1)>",
            "trust": "unknown",
        },
    )
    assert response.status_code == 303
    page = client.get(response.headers["Location"]).data
    assert b"&lt;script&gt;" in page and b"<script>alert" not in page
    assert b"&lt;img" in page and b"<img src=x" not in page
    assert not client.get("/api/device/1").json["device"]["trusted"]


def test_partial_form_cannot_silently_clear_metadata(client: FlaskClient) -> None:
    csrf = token(client)
    client.patch(
        "/api/device/1", json={"name": "NAS", "notes": "Keep this"}, headers={"X-CSRF-Token": csrf}
    )
    response = client.post("/device/1", data={"csrf_token": csrf, "trust": "unknown"})
    assert response.status_code == 400
    device = client.get("/api/device/1").json["device"]
    assert device["name"] == "NAS" and device["notes"] == "Keep this"


@pytest.mark.parametrize(
    "value",
    [
        {"command": "id"},
        {"ip": "8.8.8.8"},
        {"mac": "bad"},
        {"trusted": "true"},
        {"trusted": 1},
        {"name": 1},
        {"notes": None},
        [],
        {},
        {"name": "a" * 201},
        {"notes": "a" * 10001},
    ],
)
def test_api_rejects_arbitrary_or_invalid_fields(client: FlaskClient, value: object) -> None:
    response = client.patch("/api/device/1", json=value, headers={"X-CSRF-Token": token(client)})
    assert response.status_code == 400
    assert client.get("/api/device/1").json["device"]["name"] is None


@pytest.mark.parametrize("headers", [{}, {"X-CSRF-Token": "incorrect"}, {"X-CSRF-Token": "é"}])
def test_csrf_is_required_and_unicode_is_handled(
    client: FlaskClient, headers: dict[str, str]
) -> None:
    token(client)
    assert client.patch("/api/device/1", json={"trusted": True}, headers=headers).status_code == 403


def test_cross_origin_and_host_rebinding_denied(client: FlaskClient) -> None:
    csrf = token(client)
    assert (
        client.patch(
            "/api/device/1",
            json={"trusted": True},
            headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    assert (
        client.patch(
            "/api/device/1",
            json={"trusted": True},
            headers={"X-CSRF-Token": csrf, "Sec-Fetch-Site": "cross-site"},
        ).status_code
        == 403
    )
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
    response = client.get("/api/devices", headers={"Host": "evil.example"})
    assert response.status_code == 400 and response.json == {"error": "Untrusted Host header"}
    assert client.get("/", headers={"Host": "192.168.203.60"}).status_code == 400
    assert (
        client.patch(
            "/api/device/1",
            json={"trusted": False},
            headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"},
        ).status_code
        == 200
    )


@pytest.mark.parametrize("path", ["/device/999", "/api/device/999", "/api/scan", "/api/command"])
def test_unknown_routes_and_devices(client: FlaskClient, path: str) -> None:
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("limit", ["bad", "0", "501"])
def test_history_limits(client: FlaskClient, limit: str) -> None:
    assert client.get("/api/events?limit=" + limit).status_code == 400


def test_api_event_limit_and_health(client: FlaskClient) -> None:
    assert len(client.get("/api/events?limit=1").json["events"]) == 1
    assert client.get("/api/devices?unknown=bad").status_code == 400
    response = client.get("/healthz")
    assert response.status_code == 200 and response.json["dashboard"] == "healthy"
    assert not response.json["monitor_healthy"]


def test_no_automatic_trust_or_network_calls(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    discovery = Mock(side_effect=AssertionError("Dashboard must never scan"))
    monkeypatch.setattr("netwatch.discovery.scanner.Scanner.discover", discovery)
    for path in ("/", "/api/devices", "/api/summary", "/api/device/1"):
        assert client.get(path).status_code == 200
    discovery.assert_not_called()
    assert not client.get("/api/device/1").json["device"]["trusted"]


def test_body_size_limit(client: FlaskClient) -> None:
    assert (
        client.patch(
            "/api/device/1", data="a" * 32769, headers={"X-CSRF-Token": token(client)}
        ).status_code
        == 413
    )


def test_session_secret_permissions_and_reuse(tmp_path: Path) -> None:
    config = Config(database_path=tmp_path / "state/db.sqlite")
    first = create_app(config)
    second = create_app(config)
    assert first.secret_key == second.secret_key
    assert len(first.secret_key) == 64
    assert config.database_path.with_suffix(".web-key").stat().st_mode & 0o777 == 0o600


def test_invalid_secret_refused(tmp_path: Path) -> None:
    config = Config(database_path=tmp_path / "db.sqlite")
    config.database_path.with_suffix(".web-key").write_text("broken")
    with pytest.raises(ValueError):
        create_app(config)
