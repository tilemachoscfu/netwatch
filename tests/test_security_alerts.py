import json
import sqlite3
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_inventory import AT, OBS, result

from netwatch.database.store import MIGRATION_2, SCHEMA, Store
from netwatch.models.records import timestamp
from netwatch.notifications.alerts import NotificationService
from netwatch.notifications.telegram import message
from netwatch.services.inventory import Inventory
from netwatch.utils.config import Config, NotificationsConfig
from netwatch.web.app import create_app
from netwatch.web.auth import set_password


def provider() -> Mock:
    return Mock(security_only=True, provider_key="telegram")


@pytest.mark.parametrize("state", ["TRUSTED", "KNOWN", "UNKNOWN", "BLOCKED"])
def test_review_states_explicit_and_preserved_on_metadata_edit(store: Store, state: str) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    assert store.device("1").trust_state == "UNKNOWN"
    inventory.edit("1", trust_state=state)
    inventory.edit("1", notes="Reviewed", name="My device", set_name=True)
    device = store.device("1")
    assert device.trust_state == state and device.trusted == (state == "TRUSTED")
    assert device.notes == "Reviewed"
    assert len(store.devices(unknown_only=True)) == (state == "UNKNOWN")


def test_conflicting_review_inputs_are_atomic(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    count = len(store.events())
    with pytest.raises(ValueError):
        inventory.edit("1", trusted=True, trust_state="BLOCKED", notes="must not save")
    with pytest.raises(ValueError):
        inventory.edit("1", trust_state="APPROVED")
    assert store.device("1").notes == "" and len(store.events()) == count


@pytest.mark.parametrize("state", ["KNOWN", "BLOCKED"])
def test_legacy_revoke_audits_non_boolean_review_changes(store: Store, state: str) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    inventory.edit("1", trust_state=state)
    inventory.edit("1", trusted=False)
    assert store.device("1").trust_state == "UNKNOWN"
    event = store.events(1, 1)[0]
    assert event.kind == "trust_state_changed" and event.details == {"old": state, "new": "UNKNOWN"}


def test_event_dedup_survives_notifier_and_database_restart(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    sink = provider()
    with Store(path) as store:
        first = Inventory(store, 300).record(result(OBS), at=AT)
        notifier = NotificationService(store, (sink,))
        notifier.dispatch(first.events)
        notifier.dispatch(first.events)
    with Store(path) as store:
        NotificationService(store, (sink,)).dispatch(first.events)
        assert (
            store.connection.execute("SELECT COUNT(*) FROM notification_claims").fetchone()[0] == 1
        )
    sink.send.assert_called_once()
    alert = sink.send.call_args.args[0]
    assert alert.kind == "new_device" and alert.priority == "HIGH"
    assert "Status: UNKNOWN" in message(alert)
    assert len(message(alert)) < 1000


def test_routine_dhcp_and_online_offline_events_are_silent(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    inventory.edit("1", trusted=True)
    sink = provider()
    notifier = NotificationService(store, (sink,))
    notifier.dispatch(inventory.record(result(), at=AT + timedelta(seconds=400)).events)
    notifier.dispatch(
        inventory.record(
            result(replace(OBS, ip="192.168.203.3")), at=AT + timedelta(seconds=500)
        ).events
    )
    notifier.dispatch(
        inventory.record(
            result(replace(OBS, ip="192.168.203.3")), at=AT + timedelta(seconds=560)
        ).events
    )
    sink.send.assert_not_called()


def test_blocked_presence_cooldown_and_material_review_change(store: Store, monkeypatch) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    inventory.edit("1", trust_state="BLOCKED")
    sink = provider()
    notifier = NotificationService(store, (sink,))
    now = AT
    monkeypatch.setattr("netwatch.notifications.alerts.utc_now", lambda: now)
    first = inventory.record(result(OBS), at=AT + timedelta(seconds=60))
    notifier.dispatch(first.events)
    assert sink.send.call_count == 1
    notifier.dispatch(inventory.record(result(OBS), at=AT + timedelta(seconds=120)).events)
    assert sink.send.call_count == 1
    inventory.record(result(), at=AT + timedelta(seconds=500))
    repeated = inventory.record(result(OBS), at=AT + timedelta(seconds=600))
    notifier.dispatch(repeated.events)
    assert sink.send.call_count == 1
    now = AT + timedelta(hours=2)
    notifier.dispatch(repeated.events)  # Suppressed event cannot be replayed after cooldown.
    assert sink.send.call_count == 1
    inventory.record(result(), at=AT + timedelta(hours=2))
    notifier.dispatch(inventory.record(result(OBS), at=AT + timedelta(hours=2, seconds=60)).events)
    assert sink.send.call_count == 2
    inventory.edit("1", trust_state="KNOWN")
    inventory.edit("1", trust_state="BLOCKED")
    notifier.dispatch(inventory.record(result(OBS), at=AT + timedelta(hours=2, seconds=120)).events)
    assert sink.send.call_count == 3
    assert all(call.args[0].priority == "HIGH" for call in sink.send.call_args_list)


@pytest.mark.parametrize("state,expected", [("UNKNOWN", 0), ("KNOWN", 1), ("TRUSTED", 1)])
def test_substantial_identity_change_requires_review_and_two_signals(
    store: Store,
    state: str,
    expected: int,
) -> None:
    inventory = Inventory(store, 300)
    obs = replace(OBS, hostname="office-nas", vendor="Acme")
    inventory.record(result(obs), at=AT)
    inventory.edit("1", trust_state=state)
    sink = provider()
    notifier = NotificationService(store, (sink,))
    report = inventory.record(
        result(replace(obs, hostname="other-host", vendor="Other")), at=AT + timedelta(seconds=60)
    )
    notifier.dispatch(report.events)
    assert sink.send.call_count == expected
    if expected:
        assert sink.send.call_args.args[0].kind == "known_identity_changed"
        assert sink.send.call_args.args[0].priority == "MEDIUM"
    # A single hostname change and passive enrichment must not trigger this rule.
    report = inventory.record(
        result(replace(obs, hostname="third-host", vendor="Other")), at=AT + timedelta(seconds=120)
    )
    notifier.dispatch(report.events)
    inventory.identify("1", hostname="enriched-host", vendor="Enriched")
    notifier.dispatch(tuple(store.events(1, 2)))
    assert sink.send.call_count == expected


def test_changed_identity_bypasses_identical_state_cooldown(store: Store) -> None:
    inventory = Inventory(store, 300)
    obs = replace(OBS, hostname="original", vendor="Acme")
    inventory.record(result(obs), at=AT)
    inventory.edit("1", trust_state="KNOWN")
    sink = provider()
    notifier = NotificationService(store, (sink,))
    for seconds, hostname, vendor in ((60, "other", "Other"), (120, "third", "Third")):
        notifier.dispatch(
            inventory.record(
                result(replace(obs, hostname=hostname, vendor=vendor)),
                at=AT + timedelta(seconds=seconds),
            ).events
        )
    assert sink.send.call_count == 2


def test_different_identity_transition_to_previous_value_is_material(store: Store) -> None:
    inventory = Inventory(store, 300)
    obs = replace(OBS, hostname="original", vendor="Acme")
    inventory.record(result(obs), at=AT)
    inventory.edit("1", trust_state="KNOWN")
    sink = provider()
    notifier = NotificationService(store, (sink,))
    for index, (hostname, vendor) in enumerate(
        (("other", "Other"), ("third", "Third"), ("other", "Other"), ("third", "Third")),
        1,
    ):
        notifier.dispatch(
            inventory.record(
                result(replace(obs, hostname=hostname, vendor=vendor)),
                at=AT + timedelta(minutes=index),
            ).events
        )
    # A->B, B->C, C->B differ; the repeated B->C within one hour is identical.
    assert sink.send.call_count == 3


@pytest.mark.parametrize("hours,expected", [(1, 0), (23, 0), (24, 1), (48, 1)])
def test_only_long_absence_returns_alert(store: Store, hours: int, expected: int) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    inventory.edit("1", trusted=True)
    inventory.record(result(), at=AT + timedelta(minutes=10))
    sink = provider()
    report = inventory.record(result(OBS), at=AT + timedelta(hours=hours))
    NotificationService(store, (sink,)).dispatch(report.events)
    assert sink.send.call_count == expected
    if expected:
        assert sink.send.call_args.args[0].kind == "long_absence_return"


def test_trusted_mac_candidate_requires_unique_matching_identity(store: Store) -> None:
    inventory = Inventory(store, 300)
    obs = replace(OBS, hostname="office-nas", vendor="Acme")
    inventory.record(result(obs), at=AT)
    inventory.edit("1", trusted=True)
    changed = replace(obs, mac="02:00:00:00:00:22", ip="192.168.203.9")
    report = inventory.record(result(changed), at=AT + timedelta(seconds=60))
    sink = provider()
    NotificationService(store, (sink,)).dispatch(report.events)
    assert [call.args[0].kind for call in sink.send.call_args_list] == [
        "new_device",
        "trusted_mac_changed",
    ]
    assert store.device("2").trust_state == "UNKNOWN" and store.device("1").trusted
    assert "not proof" in message(sink.send.call_args.args[0])


def test_trusted_gateway_mac_change_uses_route_evidence_without_hostname(store: Store) -> None:
    inventory = Inventory(store, 300)
    obs = replace(OBS, hostname=None, vendor=None)
    inventory.record(result(obs), at=AT)
    inventory.edit("1", trusted=True)
    with store.transaction():
        store.save_network_context({"gateway": obs.ip})
    changed = replace(obs, mac="02:00:00:00:00:22")
    report = inventory.record(result(changed), at=AT + timedelta(seconds=60))
    sink = provider()
    NotificationService(store, (sink,)).dispatch(report.events)
    alerts = [call.args[0] for call in sink.send.call_args_list]
    assert [alert.kind for alert in alerts] == ["new_device", "trusted_mac_changed"]
    assert "kernel gateway" in alerts[-1].details["evidence"]
    assert alerts[-1].priority == "HIGH" and alerts[-1].details["candidate_only"]
    assert any(event.kind == "trusted_mac_changed" for event in store.recent_alerts())
    assert store.device("2").trust_state == "UNKNOWN"


def test_gateway_and_identity_match_do_not_duplicate_mac_warning(store: Store) -> None:
    inventory = Inventory(store, 300)
    obs = replace(OBS, hostname="my-router", vendor="Acme")
    inventory.record(result(obs), at=AT)
    inventory.edit("1", trusted=True)
    with store.transaction():
        store.save_network_context({"gateway": obs.ip})
    report = inventory.record(
        result(replace(obs, mac="02:00:00:00:00:22")), at=AT + timedelta(seconds=60)
    )
    sink = provider()
    NotificationService(store, (sink,)).dispatch(report.events)
    assert [call.args[0].kind for call in sink.send.call_args_list].count(
        "trusted_mac_changed"
    ) == 1


@pytest.mark.parametrize(
    "both_present,hostname,vendor",
    [
        (False, None, None),
        (False, "different", "Acme"),
        (False, "office-nas", "Other"),
        (True, "office-nas", "Acme"),
    ],
)
def test_dhcp_reuse_and_other_identities_never_claim_trusted_mac_change(
    store: Store,
    both_present: bool,
    hostname: str | None,
    vendor: str | None,
) -> None:
    inventory = Inventory(store, 300)
    obs = replace(OBS, hostname="office-nas", vendor="Acme")
    inventory.record(result(obs), at=AT)
    inventory.edit("1", trusted=True)
    changed = replace(obs, mac="02:00:00:00:00:22", hostname=hostname, vendor=vendor)
    observations = (replace(obs, ip="192.168.203.9"), changed) if both_present else (changed,)
    report = inventory.record(result(*observations), at=AT + timedelta(seconds=60))
    assert not any(event.kind == "trusted_mac_changed" for event in report.events)


def test_schema_two_migration_preserves_every_original_column(tmp_path: Path) -> None:
    path = tmp_path / "v2.db"
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA + MIGRATION_2)
        for ident, trusted in ((1, 0), (2, 1)):
            db.execute(
                "INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ident,
                    f"02:00:00:00:00:0{ident}",
                    f"192.168.203.{ident}",
                    None,
                    None,
                    timestamp(AT),
                    timestamp(AT),
                    1,
                    trusted,
                    None,
                    "original notes",
                    "eth0",
                ),
            )
        originals = db.execute("SELECT * FROM devices ORDER BY id").fetchall()
    path.chmod(0o600)
    with Store(path) as store:
        assert store.connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert [
            tuple(row)[:-1] for row in store.connection.execute("SELECT * FROM devices ORDER BY id")
        ] == originals
        assert [d.trust_state for d in store.devices()] == ["UNKNOWN", "TRUSTED"]
    with Store(path) as store:
        assert len(store.devices()) == 2


def test_dashboard_four_states_authentication_and_csrf(tmp_path: Path) -> None:
    config = Config(database_path=tmp_path / "web.db", web_auth_required=True)
    set_password(config, "A-test-password-1234")
    with Store(config.database_path) as store:
        inventory = Inventory(store, 300)
        for ident, state in enumerate(("UNKNOWN", "KNOWN", "TRUSTED", "BLOCKED"), 1):
            inventory.record(
                result(
                    replace(OBS, ip=f"192.168.203.{ident + 10}", mac=f"02:00:00:00:00:0{ident}")
                ),
                at=AT,
            )
            inventory.edit(str(ident), trust_state=state)
    client = create_app(config, secret_key="test-key").test_client()
    assert client.get("/devices").status_code == 401
    assert client.get("/api/devices").status_code == 401
    headers = {
        "Authorization": "Basic "
        + __import__("base64").b64encode(b"netwatch:A-test-password-1234").decode()
    }
    summary = client.get("/api/summary", headers=headers).json
    assert all(summary[state] == 1 for state in ("unknown", "known", "trusted", "blocked"))
    for state in ("unknown", "known", "trusted", "blocked"):
        rows = client.get("/api/devices?trust=" + state, headers=headers).json["devices"]
        assert len(rows) == 1 and rows[0]["trust_state"] == state.upper()
    assert (
        client.patch("/api/device/1", json={"trust_state": "TRUSTED"}, headers=headers).status_code
        == 403
    )
    csrf = client.get("/api/csrf", headers=headers).json["csrf_token"]
    headers["X-CSRF-Token"] = csrf
    for invalid in ("ADMIN", [], True, None):
        assert (
            client.patch(
                "/api/device/1", json={"trust_state": invalid}, headers=headers
            ).status_code
            == 400
        )
    assert (
        client.patch(
            "/api/device/1", json={"trusted": True, "trust_state": "BLOCKED"}, headers=headers
        ).status_code
        == 400
    )
    response = client.patch("/api/device/1", json={"trust_state": "KNOWN"}, headers=headers)
    assert response.status_code == 200 and response.json["device"]["trust_state"] == "KNOWN"
    assert "BLOCKED" in client.get("/device/1", headers=headers).text


@pytest.mark.parametrize(
    "field,value",
    [
        ("security_cooldown", 3599),
        ("security_cooldown", float("inf")),
        ("security_cooldown", True),
        ("long_absence", 0),
    ],
)
def test_security_notification_config_rejects_unsafe_values(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        NotificationsConfig(**{field: value})


def test_claims_never_contain_notification_credentials(store: Store) -> None:
    report = Inventory(store, 300).record(result(OBS), at=AT)
    NotificationService(store, (provider(),)).dispatch(report.events)
    row = store.connection.execute("SELECT details FROM notification_claims").fetchone()
    assert json.loads(row[0])["priority"] == "HIGH"


def test_security_provider_failure_is_redacted_and_does_not_replay(store: Store, caplog) -> None:
    report = Inventory(store, 300).record(result(OBS), at=AT)
    sink = provider()
    sink.send.side_effect = RuntimeError("private-provider-error")
    notifier = NotificationService(store, (sink,))
    notifier.dispatch(report.events)
    notifier.dispatch(report.events)
    assert sink.send.call_count == 1
    assert "private-provider-error" not in caplog.text
    assert "Security notification failed" in caplog.text
    assert len(store.devices()) == 1
