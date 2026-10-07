import json
import sqlite3
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_inventory import AT, OBS, result

from netwatch.database.store import Store
from netwatch.services.fingerprints import (
    FingerprintService,
    fingerprint,
    local_dhcp,
    parse_dhcp,
    topology,
)
from netwatch.services.inventory import Inventory
from netwatch.utils.config import Config


@pytest.mark.parametrize(
    "label,category",
    [
        ("Office Macbook", "Computer"),
        ("iPhone", "Mobile Device"),
        ("iPad", "Tablet"),
        ("Living Room Smart TV", "Smart TV"),
        ("doorbell", "IoT"),
        ("gateway", "Network Equipment"),
        ("Printer", "Printer"),
        ("Office NAS", "Server"),
        ("Apple", "Unknown"),
    ],
)
def test_explainable_categories(store: Store, label: str, category: str) -> None:
    Inventory(store, 300).record(result(OBS), at=AT)
    device = replace(store.device("1"), name=label, hostname=None, vendor="Apple, Inc.")
    value = fingerprint(device, previous_ips=["192.168.203.9"])
    assert value["category"] == category
    assert value["evidence"] and "model" not in value
    assert any(item["source"] == "historical_ips" for item in value["evidence"])
    if category == "Unknown":
        assert value["confidence"] == "unknown"


def test_conflicting_hints_remain_unknown_and_vendor_alone_inconclusive(store: Store) -> None:
    Inventory(store, 300).record(result(OBS), at=AT)
    device = replace(store.device("1"), name="NAS", hostname="iphone", vendor="Apple")
    value = fingerprint(device, previous_ips=[])
    assert value["category"] == "Unknown" and value["confidence"] == "unknown"
    assert any(item["source"] == "conflict" for item in value["evidence"])
    value = fingerprint(replace(device, name=None, hostname=None), previous_ips=[])
    assert value["category"] == "Unknown"


def test_gateway_is_role_evidence_not_model(store: Store) -> None:
    Inventory(store, 300).record(result(OBS), at=AT)
    value = fingerprint(replace(store.device("1"), hostname=None), previous_ips=[], gateway=OBS.ip)
    assert value["category"] == "Network Equipment" and value["confidence"] == "high"
    assert any(item["source"] == "kernel_default_route" for item in value["evidence"])


def test_passive_dhcp_requires_current_matching_lease(tmp_path: Path) -> None:
    expiry = int((AT + timedelta(hours=1)).timestamp())
    payload = (
        f"{expiry} {OBS.mac} {OBS.ip} iPhone *\n"
        f"1 {OBS.mac} 192.168.203.9 expired *\nmalformed\n"
        f"0 bad {OBS.ip} bogus\n0 {OBS.mac} 192.168.203.8 * *"
    )
    values = parse_dhcp(payload, at=AT)
    assert values == {(OBS.mac, OBS.ip): "iPhone"}
    path = tmp_path / "dnsmasq.leases"
    path.write_text(payload)
    assert local_dhcp((path, tmp_path / "missing"), at=AT) == values
    path.write_text("x" * 1048577)
    assert not local_dhcp((path,), at=AT)


def test_conflicting_local_dhcp_records_are_not_used_as_identity(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    first.write_text(f"0 {OBS.mac} {OBS.ip} iPhone *")
    second.write_text(f"0 {OBS.mac} {OBS.ip} Printer *")
    assert not local_dhcp((first, second), at=AT)
    assert not parse_dhcp(first.read_text() + "\n" + second.read_text(), at=AT)


def test_refresh_preserves_observations_events_trust_and_unchanged_timestamp(store: Store) -> None:
    Inventory(store, 300).record(result(OBS), at=AT)
    service = FingerprintService(store, Config())
    service.refresh()
    before = store.fingerprint(1)
    service.refresh()
    assert store.fingerprint(1) == before
    assert len(store.events()) == len(store.observations(1)) == 1
    assert not store.device("1").trusted
    Inventory(store, 300).edit("1", name="Office NAS", set_name=True)
    service.refresh()
    assert store.fingerprint(1)["category"] == "Server"


def test_dhcp_evidence_does_not_claim_a_liveness_observation(store: Store, tmp_path: Path) -> None:
    Inventory(store, 300).record(result(OBS), at=AT)
    path = tmp_path / "leases"
    path.write_text(f"0 {OBS.mac} {OBS.ip} iPad *")
    store.set_offline(1)
    before = store.device("1")
    FingerprintService(store, Config(dhcp_files=(path,))).refresh()
    value = store.fingerprint(1)
    assert value["category"] == "Tablet"
    assert store.device("1") == before and len(store.observations(1)) == 1


def test_topology_parsing_is_bounded_to_configured_interface_and_private_subnet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = Mock(
        side_effect=[
            json.dumps([{"addr_info": [{"local": "192.168.203.60"}, {"local": "8.8.8.8"}]}]),
            json.dumps(
                [
                    {"dev": "eno1", "gateway": "192.168.203.1"},
                    {"dev": "other", "gateway": "10.0.0.1"},
                ]
            ),
        ]
    )
    monkeypatch.setattr("netwatch.services.fingerprints.run_command", runner)
    value = topology(Config(subnet="192.168.203.0/24", interface="eno1"))
    assert value["gateway"] == "192.168.203.1" and value["local_ip"] == "192.168.203.60"
    assert runner.call_count == 2
    runner.side_effect = ["null", "[]"]
    assert topology(Config(subnet="192.168.203.0/24", interface="eno1")) == {}


def test_startup_without_lan_address_preserves_recorded_gateway(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    Inventory(store, 300).record(result(OBS), at=AT)
    config = Config(subnet="192.168.203.0/24", interface="eno1")
    recorded = {
        "interface": "eno1",
        "subnet": config.subnet,
        "local_ip": "192.168.203.60",
        "gateway": "192.168.203.1",
        "observed_at": AT.isoformat(),
    }
    store.save_network_context(recorded)
    before = store.device("1")
    monkeypatch.setattr(
        "netwatch.services.fingerprints.run_command",
        Mock(side_effect=[json.dumps([{"addr_info": []}]), "[]"]),
    )
    FingerprintService(store, config).refresh(collect_topology=True)
    assert store.network_context() == recorded
    assert store.device("1") == before
    assert len(store.events()) == len(store.observations(1)) == 1


def test_connected_lan_without_default_route_does_not_invent_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "netwatch.services.fingerprints.run_command",
        Mock(side_effect=[json.dumps([{"addr_info": [{"local": "192.168.203.60"}]}]), "[]"]),
    )
    value = topology(Config(subnet="192.168.203.0/24", interface="eno1"))
    assert value["local_ip"] == "192.168.203.60" and value["gateway"] is None


def test_schema_one_migration_is_additive_idempotent_and_preserves_history(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    with Store(path) as store:
        Inventory(store, 300).record(result(OBS), at=AT)
        Inventory(store, 300).edit("1", name="NAS", trusted=True, set_name=True)
        before = store.device("1")
        events = store.events()
        observations = store.observations(1)
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "DROP TABLE fingerprints; DROP TABLE network_context; "
            "DROP TABLE notification_claims; ALTER TABLE devices DROP COLUMN trust_state; "
            "PRAGMA user_version=1;"
        )
    with pytest.raises(ValueError):
        Store(path, readonly=True)
    for _ in range(2):
        with Store(path) as store:
            assert store.connection.execute("PRAGMA user_version").fetchone()[0] == 3
            assert store.device("1") == before and store.events() == events
            assert store.observations(1) == observations
            FingerprintService(store, Config()).refresh()
            assert store.fingerprint(1)["category"] == "Server"
            assert store.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
