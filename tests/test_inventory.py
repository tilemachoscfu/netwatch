from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from netwatch.database.store import Store
from netwatch.models.records import DiscoveryResult, Observation
from netwatch.services.inventory import Inventory

AT = datetime(2026, 1, 1, tzinfo=UTC)
OBS = Observation("192.168.203.2", "00:11:22:33:44:55", "host", "Vendor")


def result(
    *observations: Observation,
    complete: bool = True,
    subnet: str = "192.168.203.0/24",
    interface: str = "eth0",
) -> DiscoveryResult:
    return DiscoveryResult(
        observations, subnet, interface, complete, () if complete else ("failure",)
    )


def test_new_device_and_immutable_history(store: Store) -> None:
    inventory = Inventory(store, 300)
    first = inventory.record(result(OBS), at=AT)
    second = inventory.record(result(OBS), at=AT + timedelta(seconds=60))
    device = store.by_mac(OBS.mac)
    assert device is not None and device.online and not device.trusted
    assert len(first.new_devices) == 1 and first.events[0].kind == "new_device"
    assert not second.new_devices and not second.events
    history = store.observations(device.id)
    assert len(history) == 2 and history[0]["scan_id"] != history[1]["scan_id"]
    assert device.first_seen == history[1]["observed_at"]
    assert device.last_seen == history[0]["observed_at"]


def test_offline_and_online_transitions(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    assert not inventory.record(result(), at=AT + timedelta(seconds=299)).events
    offline = inventory.record(result(), at=AT + timedelta(seconds=300))
    assert [event.kind for event in offline.events] == ["device_offline"]
    assert not store.device("1").online
    assert not inventory.record(result(), at=AT + timedelta(seconds=400)).events
    online = inventory.record(result(OBS), at=AT + timedelta(seconds=500))
    assert [event.kind for event in online.events] == ["device_online"]
    assert store.device("1").online


def test_failed_discovery_does_not_mark_offline(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    report = inventory.record(result(complete=False), at=AT + timedelta(seconds=1000))
    assert not report.events and not report.complete and store.device("1").online


def test_ip_hostname_vendor_change_preserves_snapshots(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    changed = replace(OBS, ip="192.168.203.3", hostname="new-host", vendor="New vendor")
    report = inventory.record(result(changed), at=AT + timedelta(seconds=60))
    assert {event.kind for event in report.events} == {
        "ip_changed",
        "hostname_changed",
        "vendor_changed",
    }
    assert len(store.devices()) == 1 and store.device("1").ip == "192.168.203.3"
    assert store.observations(1)[1]["ip"] == "192.168.203.2"
    inventory.record(
        result(replace(changed, hostname=None, vendor=None)), at=AT + timedelta(seconds=120)
    )
    assert store.device("1").hostname == "new-host" and store.device("1").vendor == "New vendor"
    assert store.observations(1)[0]["hostname"] is None


def test_trust_and_metadata_survive_scans(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    inventory.edit("1", trusted=True, name="NAS", notes="Office", set_name=True)
    inventory.record(result(OBS), at=AT + timedelta(seconds=60))
    device = store.device("NAS")
    assert device.trusted and device.name == "NAS" and device.notes == "Office"
    assert not store.devices(unknown_only=True)
    before = len(store.events())
    inventory.edit("1", trusted=True)
    assert len(store.events()) == before
    inventory.edit("1", trusted=False)
    assert len(store.devices(unknown_only=True)) == 1


def test_ip_reuse_does_not_merge_mac_identity(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    inventory.edit("1", trusted=True)
    newcomer = replace(OBS, mac="00:11:22:33:44:66")
    report = inventory.record(result(newcomer), at=AT + timedelta(seconds=60))
    assert len(store.devices()) == 2
    assert not store.device("2").trusted
    assert [event.kind for event in report.events].count("mac_at_ip_changed") == 2
    assert not inventory.record(result(newcomer), at=AT + timedelta(seconds=120)).events
    with pytest.raises(ValueError, match="Ambiguous"):
        store.device(OBS.ip)


def test_expiration_is_scoped_to_current_lan_and_interface(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    inventory.record(result(subnet="10.0.0.0/24"), at=AT + timedelta(seconds=1000))
    inventory.record(result(interface="eth1"), at=AT + timedelta(seconds=1000))
    assert store.device("1").online


def test_mac_at_ip_change_includes_offline_history(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    inventory.record(result(), at=AT + timedelta(seconds=300))
    report = inventory.record(
        result(replace(OBS, mac="00:11:22:33:44:66")), at=AT + timedelta(seconds=400)
    )
    assert len(report.new_devices) == 1
    assert [event.kind for event in report.events].count("mac_at_ip_changed") == 2
    assert not store.device("1").online and store.device("2").online


@pytest.mark.parametrize("observation", [replace(OBS, ip="8.8.8.8"), replace(OBS, mac="bad")])
def test_invalid_observation_is_not_persisted(store: Store, observation: Observation) -> None:
    with pytest.raises(ValueError):
        Inventory(store, 300).record(result(observation), at=AT)
    assert not store.devices()
    assert store.connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_transaction_rolls_back_on_clock_regression(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    with pytest.raises(ValueError, match="precedes"):
        inventory.record(result(replace(OBS, ip="192.168.203.9")), at=AT - timedelta(seconds=1))
    assert store.device("1").ip == OBS.ip
    assert len(store.observations(1)) == 1
    assert store.connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


def test_duplicate_or_conflicting_evidence_rejected(store: Store) -> None:
    with pytest.raises(ValueError):
        Inventory(store, 300).record(result(OBS, replace(OBS, mac="00:11:22:33:44:66")), at=AT)
    assert not store.devices()
