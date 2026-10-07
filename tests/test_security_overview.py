from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_inventory import AT, OBS, result
from test_security import authorization

from netwatch.database.store import Store
from netwatch.models.records import timestamp
from netwatch.services.inventory import Inventory
from netwatch.services.security_overview import SecurityOverview
from netwatch.utils.config import Config
from netwatch.web.app import create_app
from netwatch.web.auth import set_password


@pytest.fixture
def network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for module in ("security_overview", "dashboard", "inventory", "monitor"):
        monkeypatch.setattr(f"netwatch.services.{module}.utc_now", lambda: AT)
    config = Config(database_path=tmp_path / "netwatch.db")
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.record(result(OBS), at=AT - timedelta(days=2))
        inventory.edit("1", name="Office NAS", trust_state="KNOWN", set_name=True)
        store.heartbeat(timestamp(AT), successful=True)
    return config, create_app(config, secret_key="isolated-test-key").test_client()


def snapshot(store: Store) -> dict[str, list[tuple]]:
    return {
        table: [tuple(row) for row in store.connection.execute(f"SELECT * FROM {table}")]
        for table in (
            "devices",
            "observations",
            "events",
            "scans",
            "notification_claims",
            "monitor_status",
            "fingerprints",
            "network_context",
        )
    }


def test_normal_reviewed_network_is_secure(network) -> None:
    _config, client = network
    security = client.get("/api/security").json
    assert security["status"] == "SECURE"
    assert security["total"] == security["online"] == security["known"] == 1
    assert security["unknown"] == security["blocked"] == 0
    assert security["new_devices_24h"] == security["security_events_24h"] == 0
    assert security["monitor_healthy"]
    assert b"SECURE" in client.get("/").data


def test_new_unknown_is_attention_and_has_review_action(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        Inventory(store, 300).record(
            result(OBS, replace(OBS, ip="192.168.203.3", mac="00:11:22:33:44:66")), at=AT
        )
    security = client.get("/api/security").json
    assert security["status"] == "ATTENTION"
    assert security["new_devices_24h"] == security["security_events_24h"] == 1
    assert security["events"][0]["severity"] == "MEDIUM"
    assert security["events"][0]["requires_review"]
    unknown = security["unknown_devices"][0]
    assert unknown["new_unknown"] and unknown["known_for"] == "0m"
    page = client.get("/").get_data(as_text=True)
    for text in ("NEW", "Review device #2", "UNKNOWN device review", "metric-warning"):
        assert text in page


def test_blocked_online_alert_does_not_require_a_new_scan_event(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        Inventory(store, 300).edit("1", trust_state="BLOCKED")
    security = client.get("/api/security").json
    assert security["status"] == "ALERT" and security["blocked"] == 1
    assert security["security_events_24h"] == 0
    assert "BLOCKED" in security["reasons"][0]
    assert b"metric-alert" in client.get("/").data


def test_reviewed_unknown_keeps_history_but_resolves_attention(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.record(
            result(OBS, replace(OBS, ip="192.168.203.3", mac="00:11:22:33:44:66")), at=AT
        )
        inventory.edit("2", trust_state="KNOWN", name="Reviewed phone", set_name=True)
    security = client.get("/api/security").json
    assert security["status"] == "SECURE"
    assert security["new_devices_24h"] == security["security_events_24h"] == 1
    assert security["events"][0]["name"] == "Reviewed phone"
    assert not security["events"][0]["requires_review"]
    assert not security["unknown_devices"]


def test_old_unknown_still_requires_review_without_a_cosmetic_new_warning(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        Inventory(store, 300).edit("1", trust_state="UNKNOWN")
    security = client.get("/api/security").json
    assert security["status"] == "ATTENTION" and security["unknown"] == 1
    assert security["unknown_devices"][0]["known_for"] == "2d 0h"
    assert not security["unknown_devices"][0]["new_unknown"]


def test_unhealthy_monitor_is_attention_and_failed_scan_preserves_last_success(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        old_success = store.latest_successful_scan()
        inventory = Inventory(store, 300)
        inventory.record(result(complete=False), at=AT)
        store.heartbeat(timestamp(AT), successful=False, running=False)
    security = client.get("/api/security").json
    assert security["status"] == "ATTENTION" and not security["monitor_healthy"]
    assert security["last_successful_scan"]["id"] == old_success["id"]
    assert client.get("/api/summary").json["last_scan"]["complete"] == 0


@pytest.mark.parametrize("window,expected", [("24h", 0), ("7d", 1), ("30d", 2)])
def test_history_windows_do_not_change_current_status(network, window: str, expected: int) -> None:
    config, client = network
    with Store(config.database_path) as store:
        # The original new-device event is 2d old, plus one 10d old and one future event.
        store.add_event(1, "new_device", timestamp(AT - timedelta(days=10)), {})
        store.add_event(1, "new_device", timestamp(AT + timedelta(days=1)), {})
        store.add_event(1, "ip_changed", timestamp(AT), {"old": "192.168.203.9", "new": OBS.ip})
    security = client.get(f"/api/security?window={window}").json
    assert security["window"] == window and security["event_count"] == expected
    assert security["status"] == "SECURE" and security["security_events_24h"] == 0
    assert b"Recent security events" in client.get(f"/?window={window}").data


@pytest.mark.parametrize(
    "query", ["window=1h", "window=31d", "window=24h;DROP TABLE events", "show_offline=yes"]
)
@pytest.mark.parametrize("route", ["/", "/security", "/api/security", "/device/1"])
def test_security_filters_are_validated(network, query: str, route: str) -> None:
    _config, client = network
    assert client.get(route + "?" + query).status_code == 400


def test_device_security_history_and_historical_ip(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.record(result(replace(OBS, ip="192.168.203.3")), at=AT)
    detail = client.get("/api/device/1?window=7d").json
    assert detail["security_events"][0]["ip"] == OBS.ip
    assert detail["device"]["ip"] == "192.168.203.3" and detail["previous_ips"] == [OBS.ip]
    assert detail["security_window"] == "7d"
    assert b"Recent security events" in client.get("/device/1?window=7d").data


def test_trusted_mac_alert_is_high_until_explicit_state_review(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.edit("1", trust_state="TRUSTED")
        store.add_event(1, "trusted_mac_changed", timestamp(AT), {"candidate_only": True})
    security = client.get("/api/security").json
    assert security["status"] == "ALERT" and security["events"][0]["severity"] == "HIGH"
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.edit("1", trust_state="KNOWN")
        inventory.edit("1", trust_state="TRUSTED")
    security = client.get("/api/security").json
    assert security["status"] == "SECURE"
    assert not security["events"][0]["requires_review"]
    assert security["event_count"] == 1


def test_blocked_offline_history_is_not_an_active_alert(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.edit("1", trust_state="BLOCKED")
        inventory.record(result(OBS), at=AT)
        store.set_offline(1)
    security = client.get("/api/security").json
    assert security["status"] == "SECURE" and security["blocked"] == 1
    assert security["events"][0]["kind"] == "blocked_device_online"
    assert not security["events"][0]["requires_review"]


def test_identity_policy_reused_and_notification_claim_evidence_deduplicated(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        changed = replace(OBS, hostname="new-identity", vendor="Changed vendor")
        report = Inventory(store, 300).record(result(changed), at=AT)
        event = next(e for e in report.events if e.kind == "hostname_changed")
        for provider in ("telegram", "future-provider"):
            store.claim_notification(
                provider=provider,
                event_id=event.id,
                kind="known_identity_changed",
                device_id=1,
                state_key="test-key",
                at=timestamp(AT),
                cutoff=timestamp(AT - timedelta(hours=1)),
                details={"priority": "MEDIUM"},
            )
    security = client.get("/api/security").json
    assert security["status"] == "ATTENTION"
    assert security["event_count"] == security["security_events_24h"] == 1
    assert security["events"][0]["kind"] == "known_identity_changed"


def test_long_absence_is_security_evidence_but_routine_reconnect_and_dhcp_are_not(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.record(result(), at=AT - timedelta(hours=1))
        inventory.record(result(OBS), at=AT)
    security = client.get("/api/security").json
    assert security["status"] == "ATTENTION"
    assert security["events"][0]["kind"] == "long_absence_return"
    with Store(config.database_path) as store:
        # Replace only isolated fixture history, not production records.
        store.connection.execute("DELETE FROM events WHERE kind='device_online'")
        store.add_event(1, "device_online", timestamp(AT), {"absence_seconds": 60})
        store.add_event(1, "ip_changed", timestamp(AT), {"old": OBS.ip, "new": "192.168.203.8"})
    assert client.get("/api/security").json["status"] == "SECURE"


def test_gateway_map_is_logical_and_offline_toggle_does_not_change_inventory(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.record(
            result(OBS, replace(OBS, ip="192.168.203.3", mac="00:11:22:33:44:66")), at=AT
        )
        store.set_offline(2)
        store.save_network_context({"gateway": OBS.ip})
    online = client.get("/api/security").json
    all_devices = client.get("/api/security?show_offline=true").json
    assert online["map"]["gateway"]["id"] == 1
    assert sum(len(g["devices"]) for g in online["map"]["groups"]) == 0
    assert sum(len(g["devices"]) for g in all_devices["map"]["groups"]) == 1
    assert online["total"] == all_devices["total"] == 2
    assert b"physical topology" in client.get("/").data


def test_opening_and_refreshing_dashboard_is_readonly_and_never_sends_telegram(
    network, monkeypatch
) -> None:
    config, client = network
    forbidden = Mock(side_effect=AssertionError("Dashboard must not instantiate notifications"))
    monkeypatch.setattr("netwatch.notifications.telegram.configured_telegram", forbidden)
    monkeypatch.setattr("netwatch.notifications.alerts.NotificationService", forbidden)
    with Store(config.database_path) as store:
        before = snapshot(store)
    for _ in range(2):
        for route in (
            "/",
            "/security",
            "/api/security",
            "/api/summary",
            "/api/device/1",
            "/device/1",
        ):
            assert client.get(route).status_code == 200
    forbidden.assert_not_called()
    with Store(config.database_path) as store:
        assert snapshot(store) == before


def test_new_views_require_authentication_and_escape_names_without_serializing_details(
    network,
) -> None:
    config, _client = network
    attack = '<img src=x onerror="alert(1)">'
    secret_marker = "synthetic-private-detail-not-for-display"
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        inventory.edit("1", name=attack, notes=secret_marker, trust_state="UNKNOWN", set_name=True)
        store.add_event(1, "new_device", timestamp(AT), {"token": secret_marker})
    # This is a generated test-only credential, never a production secret.
    password = "test-only-passphrase-12345"
    set_password(config, password)
    client = create_app(config, secret_key="isolated-test-key").test_client()
    for route in ("/security", "/api/security", "/?window=7d"):
        assert client.get(route).status_code == 401
        response = client.get(route, headers=authorization(password))
        assert response.status_code == 200
        assert secret_marker.encode() not in response.data
        if not route.startswith("/api/"):
            assert b"<img src=x" not in response.data and b"&lt;img" in response.data
    assert (
        client.get(
            "/api/security", headers={**authorization(password), "Host": "evil.example"}
        ).status_code
        == 400
    )


def test_concurrent_monitor_write_cannot_mix_device_and_event_snapshots(
    network, monkeypatch
) -> None:
    config, client = network
    original = Store.events_between
    injected = False

    def concurrent_write(reader, *args, **kwargs):
        nonlocal injected
        if not injected:
            injected = True
            with Store(config.database_path) as writer:
                Inventory(writer, 300).record(
                    result(OBS, replace(OBS, ip="192.168.203.3", mac="00:11:22:33:44:66")), at=AT
                )
        return original(reader, *args, **kwargs)

    monkeypatch.setattr(Store, "events_between", concurrent_write)
    response = client.get("/api/security")
    assert response.status_code == 200
    assert response.json["total"] == 1 and response.json["security_events_24h"] == 0
    assert client.get("/api/security").json["total"] == 2


def test_full_counts_are_not_capped_by_the_recent_event_display(network) -> None:
    config, client = network
    with Store(config.database_path) as store:
        for _ in range(105):
            store.add_event(1, "new_device", timestamp(AT), {})
    security = client.get("/api/security").json
    assert len(security["events"]) == 100
    assert security["event_count"] == security["security_events_24h"] == 105


def test_missing_scan_unknown_age_and_no_gateway_are_safe(tmp_path: Path) -> None:
    config = Config(database_path=tmp_path / "empty.db")
    with Store(config.database_path) as store:
        empty = SecurityOverview(store, config, at=AT).overview()
        assert empty["last_successful_scan"] is None and empty["map"]["gateway"] is None
        Inventory(store, 300).record(result(OBS), at=AT)
        for first_seen in (
            "not-a-date",
            timestamp(AT + timedelta(days=1)),
            timestamp(AT - timedelta(minutes=90)),
        ):
            store.connection.execute("UPDATE devices SET first_seen=?", (first_seen,))
            overview = SecurityOverview(store, config, at=AT).overview()
            assert overview["unknown_devices"][0]["known_for"] in ("Unknown", "1h 30m")


def test_read_queries_are_parameterized_and_support_offset_timestamps(network) -> None:
    config, _client = network
    with Store(config.database_path) as store:
        store.add_event(1, "trusted_mac_changed", "2026-01-01T02:00:00+02:00", {})
        assert not store.events_between(timestamp(AT - timedelta(hours=1)), timestamp(AT), ())
        assert not store.events_between(
            timestamp(AT - timedelta(hours=1)), timestamp(AT), ("x');DROP TABLE events;--",)
        )
        events = store.events_between(
            timestamp(AT - timedelta(hours=1)), timestamp(AT), ("trusted_mac_changed",), 1
        )
        assert len(events) == 1
        assert len(store.devices()) == 1
        assert store.observation_identity(1, timestamp(AT - timedelta(days=10))) is None
