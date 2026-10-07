import io
import sqlite3
import threading
from datetime import timedelta
from unittest.mock import Mock

import pytest
from test_inventory import AT, OBS, result

from netwatch.database.store import Store
from netwatch.models.records import timestamp
from netwatch.services.inventory import Inventory
from netwatch.services.monitor import Monitor, check_health
from netwatch.utils.config import Config, NotificationsConfig
from netwatch.utils.process import DiscoveryError


class StopAfterIterations(threading.Event):
    def __init__(self, iterations: int) -> None:
        super().__init__()
        self.iterations = iterations
        self.waits = 0

    def wait(self, timeout: float | None = None) -> bool:
        self.waits += 1
        if self.waits >= self.iterations:
            self.set()
        return self.is_set()


def test_monitor_recovers_after_discovery_failure(
    store: Store, caplog: pytest.LogCaptureFixture
) -> None:
    scanner = Mock()
    scanner.discover.side_effect = [DiscoveryError("network down"), result(OBS)]
    stop = StopAfterIterations(2)
    output = io.StringIO()
    monitor = Monitor(Config(), store, scanner, output, stop=stop, clock=lambda: AT)
    monitor.run()
    assert scanner.discover.call_count == 2 and stop.waits == 2
    assert len(store.devices()) == 1
    assert "will retry" in caplog.text
    assert "NEW DEVICE DETECTED" in output.getvalue()
    assert store.connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 2
    status = store.monitor_status()
    assert status is not None and not status["running"] and status["last_success"] == timestamp(AT)


def test_monitor_failed_scan_does_not_expire_inventory(store: Store) -> None:
    Inventory(store, 300).record(result(OBS), at=AT)
    scanner = Mock()
    scanner.discover.side_effect = DiscoveryError("unavailable")
    Monitor(
        Config(),
        store,
        scanner,
        io.StringIO(),
        stop=StopAfterIterations(1),
        clock=lambda: AT + timedelta(seconds=1000),
    ).run()
    assert store.device("1").online


def test_monitor_notifications_once_and_optional(store: Store) -> None:
    scanner = Mock()
    scanner.discover.return_value = result(OBS)
    output = io.StringIO()
    monitor = Monitor(Config(), store, scanner, output, clock=lambda: AT)
    monitor.scan_once()
    monitor.scan_once()
    assert output.getvalue().count("NEW DEVICE DETECTED") == 1
    assert f"MAC: {OBS.mac}" in output.getvalue()


def test_disabled_notifications(store: Store) -> None:
    scanner = Mock()
    scanner.discover.return_value = result(OBS)
    output = io.StringIO()
    Monitor(
        Config(notifications=NotificationsConfig(console=False)),
        store,
        scanner,
        output,
        clock=lambda: AT,
    ).scan_once()
    assert not output.getvalue()


def test_notification_failure_preserves_committed_inventory(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "netwatch.notifications.alerts.notify_new_device", Mock(side_effect=BrokenPipeError())
    )
    scanner = Mock()
    scanner.discover.return_value = result(OBS)
    assert (
        Monitor(Config(), store, scanner, io.StringIO(), clock=lambda: AT).scan_once().new_devices
    )
    assert len(store.devices()) == 1


def test_monitor_recovers_from_database_error(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    monitor = Monitor(
        Config(), store, Mock(), io.StringIO(), stop=StopAfterIterations(2), clock=lambda: AT
    )
    scan = Mock(
        side_effect=[
            sqlite3.OperationalError("locked"),
            Mock(complete=True, scan_id=1, observed=0, events=()),
        ]
    )
    monkeypatch.setattr(monitor, "scan_once", scan)
    monitor.run()
    assert scan.call_count == 2


def test_health_requires_success_recent_heartbeat_and_running_monitor(store: Store) -> None:
    config = Config()
    assert not check_health(store, config, at=AT)
    store.heartbeat(timestamp(AT), successful=False)
    assert not check_health(store, config, at=AT)
    store.heartbeat(timestamp(AT), successful=True)
    assert check_health(store, config, at=AT + timedelta(seconds=300))
    assert not check_health(store, config, at=AT + timedelta(seconds=301))
    store.heartbeat(timestamp(AT + timedelta(seconds=400)), successful=False)
    assert not check_health(store, config, at=AT + timedelta(seconds=400))
    assert not check_health(store, config, at=AT - timedelta(seconds=1))
    store.heartbeat(timestamp(AT), successful=True, running=False)
    assert not check_health(store, config, at=AT)


def test_corrupt_health_timestamps_fail_closed(store: Store) -> None:
    store.heartbeat("bad", successful=True)
    assert not check_health(store, Config(), at=AT)


def test_fingerprint_failure_does_not_stop_repeated_scans(
    store: Store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = Mock()
    scanner.discover.return_value = result(OBS)
    refresh = Mock(side_effect=[sqlite3.OperationalError("unavailable"), None])
    monkeypatch.setattr("netwatch.services.monitor.FingerprintService.refresh", refresh)
    output = io.StringIO()
    Monitor(Config(), store, scanner, output, stop=StopAfterIterations(2), clock=lambda: AT).run()
    assert len(store.observations(1)) == 2 and len(store.devices()) == 1
    assert output.getvalue().count("NEW DEVICE DETECTED") == 1


def test_missing_telegram_credentials_never_stop_monitor(store: Store) -> None:
    scanner = Mock()
    scanner.discover.return_value = result(OBS)
    monitor = Monitor(
        Config(notifications=NotificationsConfig(telegram=True)),
        store,
        scanner,
        io.StringIO(),
        stop=StopAfterIterations(2),
        clock=lambda: AT,
    )
    monitor.run()
    assert scanner.discover.call_count == 2 and len(store.observations(1)) == 2
