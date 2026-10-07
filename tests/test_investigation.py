"""Investigation is passive, authenticated, bounded and never mutates inventory."""

import json
import sqlite3
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
from netwatch.services.investigation import (
    InvestigationBusy,
    InvestigationService,
    age_seconds,
    latest,
)
from netwatch.utils.config import Config
from netwatch.web.app import create_app
from netwatch.web.auth import set_password


@pytest.fixture
def investigation(store, monkeypatch):
    store.initialize_investigations()
    monkeypatch.setattr("netwatch.services.investigation.utc_now", lambda: AT)
    config = Config(
        database_path=Path(store.connection.execute("PRAGMA database_list").fetchone()[2])
    )
    return store, config, InvestigationService(store, config)


def record(store, *items, when=AT):
    return Inventory(store, 300).record(result(*(items or (OBS,))), at=when)


def test_passive_persistence_no_inventory_or_notification_changes(investigation, monkeypatch):
    store, config, service = investigation
    record(store)
    Inventory(store, 300).edit("1", notes="Private notes retained only in inventory")
    forbidden = Mock(side_effect=AssertionError("No network or notification permitted"))
    monkeypatch.setattr("netwatch.discovery.scanner.Scanner.discover", forbidden)
    monkeypatch.setattr("netwatch.notifications.telegram.TelegramProvider.send", forbidden)
    before = store.devices(), store.events(), store.observations(1)
    run = service.run(1)
    assert run["status"] == "Complete"
    assert run["result"]["confidence"] == "INSUFFICIENT"
    assert run["result"]["mode"] == "passive"
    assert all(e["mode"] == "passive" for e in run["result"]["evidence"])
    assert "Private notes retained" not in json.dumps(run)
    assert (store.devices(), store.events(), store.observations(1)) == before
    assert store.connection.execute("SELECT COUNT(*) FROM notification_claims").fetchone()[0] == 0
    forbidden.assert_not_called()
    with Store(config.database_path, readonly=True) as restarted:
        assert latest(restarted, 1) == run
    assert store.connection.execute("PRAGMA user_version").fetchone()[0] == 3


@pytest.mark.parametrize("state", ["TRUSTED", "KNOWN", "BLOCKED"])
def test_reviewed_devices_are_rejected_without_changes(investigation, state):
    store, _, service = investigation
    record(store)
    Inventory(store, 300).edit("1", trust_state=state)
    before = store.devices(), store.events()
    with pytest.raises(ValueError, match="UNKNOWN"):
        service.run(1)
    assert (store.devices(), store.events()) == before
    assert not store.investigations(1)


@pytest.mark.parametrize("selector", [0, -1, 999, 10**100])
def test_invalid_id(investigation, selector):
    with pytest.raises(ValueError, match="Device not found"):
        investigation[2].run(selector)


@pytest.mark.parametrize(
    "vendor", ["LG", "LiteON", "Lenovo", "Guangzhou Shirui Electronic Co., Ltd"]
)
def test_vendor_alone_never_identifies_category(investigation, vendor):
    store, _, service = investigation
    record(store, replace(OBS, hostname=None, vendor=vendor))
    value = service.run(1)["result"]
    assert value["category"] == "Unknown"
    assert value["confidence"] == "INSUFFICIENT"
    assert value["possible_identity"] == "Insufficient evidence"


@pytest.mark.parametrize(
    ("hostname", "category"),
    [
        ("iphone-office", "Phone"),
        ("workstation", "Computer"),
        ("proxmox", "Server"),
        ("bravia", "Smart TV"),
        ("chromecast-room", "Streaming device"),
        ("camera", "Camera"),
        ("doorbell", "Doorbell"),
        ("air-conditioner", "Air conditioner"),
        ("washing-machine", "Smart appliance"),
        ("sensor", "IoT device"),
        ("access-point", "Network infrastructure"),
    ],
)
def test_explainable_category_hints_and_repetition(investigation, hostname, category):
    store, _, service = investigation
    observation = replace(OBS, hostname=hostname)
    record(store, observation)
    assert service.collect(1, AT)["confidence"] == "LOW"
    record(store, observation, when=AT + timedelta(minutes=1))
    value = service.run(1)["result"]
    assert value["category"] == category and value["confidence"] == "MEDIUM"
    assert any(hostname in reason for reason in value["reasons"])


def test_conflicting_historical_category_hints_lower_confidence(investigation):
    store, _, service = investigation
    record(store, replace(OBS, hostname="iphone"))
    record(store, replace(OBS, hostname="bravia"), when=AT + timedelta(minutes=1))
    value = service.run(1)["result"]
    assert value["category"] == "Unknown" and value["confidence"] == "LOW"
    assert any("conflicting device categories" in c for c in value["conflicting_evidence"])


@pytest.mark.parametrize("mac", ["02:11:22:33:44:55", "not-a-mac;$(touch nope)"])
def test_private_or_malformed_mac_handled_safely(investigation, mac):
    store, _, service = investigation
    record(store, replace(OBS, hostname="iphone"))
    record(store, replace(OBS, hostname="iphone"), when=AT + timedelta(minutes=1))
    store.connection.execute("UPDATE devices SET mac=? WHERE id=1", (mac,))
    value = service.run(1)["result"]
    assert value["confidence"] == "LOW" and value["conflicting_evidence"]


def test_presence_never_infers_usage_from_single_observation(investigation):
    store, _, service = investigation
    record(store, when=AT - timedelta(hours=20))
    value = service.run(1)["result"]
    assert value["presence_pattern"].startswith("Seen once approximately 20 hours ago")
    assert "insufficient observations" in value["presence_pattern"]


def test_stale_recent_intermittent_and_empty_presence(investigation):
    store, _, service = investigation
    assert service.presence("", "", 0, [], AT, {}) == (
        "No observations recorded; presence pattern is unknown."
    )
    assert "unknown time" in service.presence("bad", "", 1, [], AT, {})
    record(store, when=AT - timedelta(days=30))
    record(store, when=AT - timedelta(days=29))
    assert "Historical/stale" in service.collect(1, AT)["presence_pattern"]
    record(store, when=AT)
    assert "Repeated observations" in service.collect(1, AT)["presence_pattern"]
    store.add_event(1, "device_offline", timestamp(AT), {})
    assert "Intermittent" in service.collect(1, AT)["presence_pattern"]
    store.connection.execute("UPDATE devices SET first_seen=?", (timestamp(AT),))
    assert "Recently appeared" in service.collect(1, AT)["presence_pattern"]
    assert age_seconds("2026-01-01T00:00:00", AT) == float("inf")


@pytest.mark.parametrize("private", [False, True])
def test_match_suggestions_do_not_merge_or_transfer_trust(investigation, private):
    store, _, service = investigation
    record(
        store,
        replace(OBS, hostname="family-iphone"),
        replace(
            OBS,
            mac="02:11:22:33:44:66" if private else "00:11:22:33:44:66",
            ip="192.168.203.3",
            hostname="family-iphone",
        ),
    )
    Inventory(store, 300).edit("1", trust_state="TRUSTED", name="Family phone", set_name=True)
    before = store.devices()
    value = service.run(2)["result"]
    assert value["possible_matches"][0]["device_id"] == 1
    assert value["possible_matches"][0]["confidence"] == "MEDIUM"
    assert store.devices() == before
    assert store.device("2").trust_state == "UNKNOWN"
    if private:
        assert "private/randomized MAC possible" in value["possible_matches"][0]["possibilities"]


@pytest.mark.parametrize("hostname", ["family-iphone2", "unrelated"])
def test_similar_hostname_and_reused_ip_are_weak_matches(investigation, hostname):
    store, _, service = investigation
    record(
        store,
        replace(OBS, hostname="family-iphone"),
        replace(OBS, mac="00:11:22:33:44:66", ip="192.168.203.3", hostname=hostname),
    )
    Inventory(store, 300).edit("1", trust_state="KNOWN")
    store.connection.execute("UPDATE devices SET ip=? WHERE id=2", (OBS.ip,))
    value = service.run(2)["result"]
    assert value["possible_matches"][0]["confidence"] == "LOW"
    assert any("Same recorded IP" in r for r in value["possible_matches"][0]["reasons"])


def test_local_dhcp_and_fresh_gateway_evidence(investigation, tmp_path):
    store, config, _ = investigation
    record(store)
    leases = tmp_path / "leases"
    leases.write_text(f"0 {OBS.mac} {OBS.ip} iphone-office *\n")
    service = InvestigationService(store, replace(config, dhcp_files=(leases,)))
    value = service.collect(1, AT)
    assert value["category"] == "Phone" and value["confidence"] == "MEDIUM"
    store.save_network_context({"gateway": OBS.ip, "observed_at": timestamp(AT)})
    value = service.collect(1, AT)
    assert value["category"] == "Unknown" and value["conflicting_evidence"]
    no_dhcp = InvestigationService(store, config).collect(1, AT)
    assert no_dhcp["category"] == "Network infrastructure"
    assert no_dhcp["confidence"] == "MEDIUM"
    assert (
        InvestigationService(store, config).collect(1, AT + timedelta(hours=1))["category"]
        == "Unknown"
    )


def test_unavailable_optional_sources_are_not_errors(investigation, tmp_path):
    store, config, _ = investigation
    record(store)
    service = InvestigationService(store, replace(config, dhcp_files=(tmp_path / "missing",)))
    assert service.run(1)["status"] == "Complete"


@pytest.mark.parametrize(
    "error", [TimeoutError(), OSError(), sqlite3.OperationalError("interrupted")]
)
def test_failures_and_timeout_persist_without_inventory_changes(investigation, monkeypatch, error):
    store, _, service = investigation
    record(store)
    before = store.devices()
    monkeypatch.setattr(service, "collect", Mock(side_effect=error))
    run = service.run(1)
    assert run["status"] == "Failed" and "timed out" in run["result"]["error"]
    assert store.devices() == before and latest(store, 1)["status"] == "Failed"


def test_deadline_expires_and_sql_progress_handler_is_removed(investigation, monkeypatch):
    store, _, service = investigation
    record(store)
    monkeypatch.setattr("netwatch.services.investigation.TIMEOUT", -1)
    assert service.run(1)["status"] == "Failed"
    assert store.connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_rate_limit_retention_and_interrupted_worker(investigation, monkeypatch):
    store, _, service = investigation
    record(store)
    service.run(1)
    with pytest.raises(InvestigationBusy):
        service.run(1)
    for minute in range(1, 7):
        monkeypatch.setattr(
            "netwatch.services.investigation.utc_now",
            lambda minute=minute: AT + timedelta(minutes=minute),
        )
        service.run(1)
    assert len(store.investigations(1)) == 5
    store.start_investigation(1, timestamp(AT))
    assert latest(store, 1)["status"] == "Failed"
    assert store.investigations(1)[0]["status"] == "Investigating"
    assert len(store.investigations(1)) == 5


def test_manual_review_race_does_not_transfer_identity(investigation, monkeypatch):
    store, _, service = investigation
    record(store)
    collect = service.collect

    def review(device_id, at):
        value = collect(device_id, at)
        store.connection.execute("UPDATE devices SET trust_state='KNOWN' WHERE id=1")
        # The simulated administrator commits their own independent action.
        store.connection.commit()
        return value

    monkeypatch.setattr(service, "collect", review)
    assert service.run(1)["status"] == "Failed"
    assert store.device("1").trust_state == "KNOWN"


def test_legacy_readonly_database_needs_no_extension(store):
    record(store)
    assert store.investigations(1) == [] and latest(store, 1) is None


@pytest.fixture
def web(tmp_path, monkeypatch):
    config = Config(database_path=tmp_path / "web.db", web_auth_required=True)
    set_password(config, "isolated-investigation-password")
    app = create_app(config, secret_key="isolated-session")
    app.config.update(TESTING=True)
    with Store(config.database_path) as store:
        record(
            store,
            replace(OBS, hostname="<img src=x onerror=alert(1)>", vendor="<script>bad</script>"),
        )
    monkeypatch.setattr("netwatch.services.investigation.utc_now", lambda: AT)
    client = app.test_client()
    auth = authorization("isolated-investigation-password")
    csrf = client.get("/api/csrf", headers=auth).json["csrf_token"]
    return config, client, {**auth, "X-CSRF-Token": csrf}


def test_authenticated_form_escaped_output_and_review_controls(web):
    config, client, headers = web
    response = client.post(
        "/device/1/investigate", data={"csrf_token": headers["X-CSRF-Token"]}, headers=headers
    )
    assert response.status_code == 303 and response.headers["Location"].endswith("#investigation")
    page = client.get("/device/1", headers=headers).get_data(as_text=True)
    assert "Status: <strong>Complete" in page
    assert "&lt;img" in page and "&lt;script&gt;" in page
    assert "<img src=x" not in page and "<script>bad" not in page
    assert page.index("INVESTIGATION") < page.index("Review device")
    assert "Save device" in page
    with Store(config.database_path) as store:
        assert store.device("1").trust_state == "UNKNOWN"


@pytest.mark.parametrize(
    ("changes", "removed", "status"),
    [
        ({}, "Authorization", 401),
        ({}, "X-CSRF-Token", 403),
        ({"X-CSRF-Token": "bad"}, None, 403),
        ({"Origin": "https://evil.example"}, None, 403),
        ({"Sec-Fetch-Site": "cross-site"}, None, 403),
        ({"Host": "evil.example", "X-Forwarded-Host": "localhost"}, None, 400),
    ],
)
def test_investigation_auth_csrf_and_host_boundary(web, changes, removed, status):
    config, client, headers = web
    headers = {**headers, **changes}
    if removed:
        headers.pop(removed)
    assert client.post("/api/device/1/investigate", json={}, headers=headers).status_code == status
    with Store(config.database_path) as store:
        assert not store.investigations(1)


@pytest.mark.parametrize(
    "value", [{"ip": "8.8.8.8"}, {"mac": OBS.mac}, {"name": "TV"}, {"active": "true"}, [], None]
)
def test_browser_cannot_supply_identity_or_active_parameters(web, value):
    _, client, headers = web
    assert (
        client.post(
            "/api/device/1/investigate",
            data=json.dumps(value),
            content_type="application/json",
            headers=headers,
        ).status_code
        == 400
    )


@pytest.mark.parametrize("value", [{"ip": "192.168.203.99"}, {"hostname": "TV"}])
def test_form_rejects_identity(web, value):
    _, client, headers = web
    assert client.post("/device/1/investigate", data=value, headers=headers).status_code == 400


def test_raw_request_rejected(web):
    _, client, headers = web
    assert (
        client.post(
            "/api/device/1/investigate",
            data="arbitrary",
            content_type="text/plain",
            headers=headers,
        ).status_code
        == 400
    )


@pytest.mark.parametrize("device_id", ["999", "0", "99999999999999999999999999999999", "invalid"])
def test_invalid_web_device_id(web, device_id):
    _, client, headers = web
    assert (
        client.post(f"/api/device/{device_id}/investigate", json={}, headers=headers).status_code
        == 404
    )


@pytest.mark.parametrize("state", ["KNOWN", "TRUSTED"])
def test_known_trusted_action_hidden_and_endpoint_rejected(web, state):
    config, client, headers = web
    with Store(config.database_path) as store:
        Inventory(store, 300).edit("1", trust_state=state)
    assert b"Investigate Device" not in client.get("/device/1", headers=headers).data
    assert client.post("/api/device/1/investigate", json={}, headers=headers).status_code == 409


def test_api_success_cooldown_and_read_persistence(web):
    _, client, headers = web
    assert client.post("/api/device/1/investigate", json={}, headers=headers).status_code == 200
    assert client.post("/api/device/1/investigate", json={}, headers=headers).status_code == 429
    assert (
        client.get("/api/device/1", headers=headers).json["investigation"]["status"] == "Complete"
    )


def test_feature_requires_auth_even_if_existing_local_reads_are_public(tmp_path):
    config = Config(database_path=tmp_path / "public.db")
    client = create_app(config, secret_key="test-session").test_client()
    headers = {"X-CSRF-Token": client.get("/api/csrf").json["csrf_token"]}
    assert client.post("/api/device/1/investigate", json={}, headers=headers).status_code == 401


def test_failed_api_and_failed_page_render(web, monkeypatch):
    _, client, headers = web
    monkeypatch.setattr(InvestigationService, "collect", Mock(side_effect=TimeoutError))
    assert client.post("/api/device/1/investigate", json={}, headers=headers).status_code == 503
    assert b"timed out" in client.get("/device/1", headers=headers).data


def test_vendor_history_conflict(investigation):
    store, _, service = investigation
    record(store, replace(OBS, hostname="iphone", vendor="A"))
    record(store, replace(OBS, hostname="iphone", vendor="B"), when=AT + timedelta(minutes=1))
    value = service.run(1)["result"]
    assert value["confidence"] == "LOW"
    assert any("vendor attributions changed" in reason for reason in value["conflicting_evidence"])


def test_unicode_storage_budget_and_bounded_sample(investigation):
    store, _, service = investigation
    # Model a migrated inventory with oversized untrusted historical strings.
    record(store)
    for index in range(25):
        observation = replace(
            OBS, hostname="iphone-" + chr(0x10000 + index) * 250, vendor=chr(0x10100 + index) * 300
        )
        device = store.device("1")
        scan = store.add_scan(timestamp(AT), timestamp(AT), "192.168.203.0/24", "eth0", True, ())
        store.add_observation(scan, device, observation, timestamp(AT))
    run = service.run(1)
    assert run["status"] == "Complete"
    assert len(json.dumps(run["result"], ensure_ascii=True)) <= 60000
    assert any("abbreviated" in e for e in run["result"]["missing_evidence"])
    assert len(store.observations(1, 500)) == 26


def test_in_progress_page_and_failure_form(web, monkeypatch):
    config, client, headers = web
    with Store(config.database_path) as store:
        store.start_investigation(1, timestamp(AT))
    assert b"Evidence collection is in progress" in client.get("/device/1", headers=headers).data
    monkeypatch.setattr(
        "netwatch.services.investigation.utc_now", lambda: AT + timedelta(minutes=1)
    )
    monkeypatch.setattr(InvestigationService, "collect", Mock(side_effect=TimeoutError))
    assert client.post("/device/1/investigate", headers=headers).status_code == 303
    assert b"Investigation failed" in client.get("/device/1", headers=headers).data


def test_sql_query_is_interrupted_at_deadline(investigation, monkeypatch):
    store, _, service = investigation
    record(store)

    # Force the progress callback during a deliberately costly local query.
    def expensive(device_id, at):
        store.connection.execute(
            "WITH RECURSIVE seq(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM seq WHERE x<10000000) "
            "SELECT sum(x) FROM seq"
        ).fetchone()
        return {}

    monkeypatch.setattr(service, "collect", expensive)
    monkeypatch.setattr("netwatch.services.investigation.TIMEOUT", 0.001)
    assert service.run(1)["status"] == "Failed"
    assert store.connection.execute("SELECT 1").fetchone()[0] == 1


def test_repetition_of_unrelated_name_does_not_raise_category_confidence(investigation):
    store, _, service = investigation
    record(store, replace(OBS, hostname="generic-host"))
    record(store, replace(OBS, hostname="generic-host"), when=AT + timedelta(minutes=1))
    record(store, replace(OBS, hostname="camera"), when=AT + timedelta(minutes=2))
    value = service.run(1)["result"]
    assert value["category"] == "Camera" and value["confidence"] == "LOW"


def test_unrelated_dhcp_name_does_not_corroborate_category(investigation, tmp_path):
    store, config, _ = investigation
    record(store, replace(OBS, hostname="camera"))
    leases = tmp_path / "leases"
    leases.write_text(f"0 {OBS.mac} {OBS.ip} generic-host *\n")
    value = InvestigationService(store, replace(config, dhcp_files=(leases,))).run(1)["result"]
    assert value["category"] == "Camera" and value["confidence"] == "LOW"


@pytest.mark.parametrize("failure", [False, True])
def test_optional_reachability_is_one_bounded_selected_host_call(
    investigation, monkeypatch, failure
):
    from netwatch.utils.process import DiscoveryError

    store, config, _ = investigation
    record(store)
    config = replace(config, subnet="192.168.203.0/24", interface="eth0")
    command = Mock(side_effect=DiscoveryError("unavailable") if failure else None)
    monkeypatch.setattr("netwatch.services.investigation.run_command", command)
    before = store.devices(), store.events(), store.observations(1)
    value = InvestigationService(store, config).run(1, active=True)["result"]
    args, kwargs = command.call_args
    assert args[0] == ["ping", "-n", "-c", "1", "-W", "1", "-I", "eth0", "--", OBS.ip]
    assert 0 < kwargs["timeout"] <= 2
    assert command.call_count == 1
    assert value["mode"] == "passive + active" and value["confidence"] == "INSUFFICIENT"
    assert value["evidence"][-1]["mode"] == "active"
    assert all(e["mode"] == "passive" for e in value["evidence"][:-1])
    assert (store.devices(), store.events(), store.observations(1)) == before
    assert store.connection.execute("SELECT COUNT(*) FROM notification_claims").fetchone()[0] == 0
    if failure:
        assert "No reachability confirmation" in value["evidence"][-1]["observation"]


@pytest.mark.parametrize(
    "case", ["stale", "offline", "invalid_mac", "public_ip", "no_lan", "enough"]
)
def test_optional_discovery_skips_unsafe_targets_and_sufficient_evidence(
    investigation, monkeypatch, case
):
    store, config, _ = investigation
    record(store)
    config = replace(config, subnet="192.168.203.0/24")
    if case == "stale":
        store.connection.execute(
            "UPDATE devices SET last_seen=?", (timestamp(AT - timedelta(hours=1)),)
        )
    elif case == "offline":
        store.set_offline(1)
    elif case == "invalid_mac":
        store.connection.execute("UPDATE devices SET mac=';$(bad)' WHERE id=1")
    elif case == "public_ip":
        store.connection.execute("UPDATE devices SET ip='8.8.8.8' WHERE id=1")
    elif case == "no_lan":
        config = replace(config, subnet=None)
    elif case == "enough":
        record(store, replace(OBS, hostname="iphone"), when=AT + timedelta(minutes=1))
        record(store, replace(OBS, hostname="iphone"), when=AT + timedelta(minutes=2))
    forbidden = Mock(side_effect=AssertionError("Target must not be contacted"))
    monkeypatch.setattr("netwatch.services.investigation.run_command", forbidden)
    value = InvestigationService(store, config).run(1, active=True)["result"]
    forbidden.assert_not_called()
    assert value["mode"] == "passive" and value["active_discovery"].startswith("Not performed:")


def test_optional_reachability_obeys_remaining_deadline(investigation, monkeypatch):
    store, config, _ = investigation
    record(store)
    service = InvestigationService(store, replace(config, subnet="192.168.203.0/24"))
    value = service.collect(1, AT)
    with pytest.raises(TimeoutError):
        service.reachability(1, value, AT, -1)


def test_explicit_api_reachability_opt_in_and_defaults(web, monkeypatch):
    _, client, headers = web
    command = Mock(side_effect=AssertionError("Fixture has no configured LAN"))
    monkeypatch.setattr("netwatch.services.investigation.run_command", command)
    response = client.post("/api/device/1/investigate", json={"active": True}, headers=headers)
    assert response.status_code == 200
    assert response.json["investigation"]["result"]["mode"] == "passive"
    command.assert_not_called()


@pytest.mark.parametrize("value", ["false", "1", "on&on"])
def test_form_active_flag_validation(web, value):
    _, client, headers = web
    assert (
        client.post("/device/1/investigate", data={"active": value}, headers=headers).status_code
        == 400
    )


def test_form_active_opt_in(web, monkeypatch):
    _, client, headers = web
    command = Mock(side_effect=AssertionError("Fixture has no configured LAN"))
    monkeypatch.setattr("netwatch.services.investigation.run_command", command)
    assert (
        client.post("/device/1/investigate", data={"active": "on"}, headers=headers).status_code
        == 303
    )
    command.assert_not_called()
