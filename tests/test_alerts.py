import io
import secrets
from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock

from test_inventory import AT, OBS, result

from netwatch.database.store import Store
from netwatch.notifications.alerts import ConsoleProvider, NotificationService
from netwatch.services.inventory import Inventory


def test_all_alert_types_and_unchanged_scans_do_not_repeat(store: Store) -> None:
    inventory = Inventory(store, 300)
    output = io.StringIO()
    provider = Mock()
    service = NotificationService(store, (ConsoleProvider(output), provider))
    first = inventory.record(result(OBS), at=AT)
    service.dispatch(first.events)
    unchanged = inventory.record(result(OBS), at=AT + timedelta(seconds=60))
    service.dispatch(unchanged.events)
    assert provider.send.call_count == 1
    assert "UNKNOWN DEVICE" in output.getvalue()
    offline = inventory.record(result(), at=AT + timedelta(seconds=400))
    service.dispatch(offline.events)
    online = inventory.record(
        result(replace(OBS, ip="192.168.203.3")), at=AT + timedelta(seconds=500)
    )
    service.dispatch(online.events)
    kinds = [call.args[0].kind for call in provider.send.call_args_list]
    assert kinds == ["new_device", "device_offline", "device_online", "ip_changed"]
    assert "DEVICE OFFLINE" in output.getvalue() and "DEVICE ONLINE AGAIN" in output.getvalue()
    assert "IP ADDRESS CHANGED" in output.getvalue()


def test_provider_failure_isolated_and_non_alert_events_ignored(store: Store) -> None:
    inventory = Inventory(store, 300)
    first = inventory.record(result(OBS), at=AT)
    failed = Mock()
    failed.send.side_effect = RuntimeError("provider failed")
    healthy = Mock()
    NotificationService(store, (failed, healthy)).dispatch(first.events)
    healthy.send.assert_called_once()
    inventory.edit("1", name="NAS", set_name=True)
    NotificationService(store, (healthy,)).dispatch(tuple(store.events(1, 1)))
    assert healthy.send.call_count == 1 and store.device("1").name == "NAS"


def test_flush_and_shutdown_failures_are_isolated_and_redacted(store: Store, caplog) -> None:
    sensitive = secrets.token_urlsafe(32)
    provider = Mock()
    provider.flush.side_effect = RuntimeError(sensitive)
    provider.close.side_effect = RuntimeError(sensitive)
    service = NotificationService(store, (provider,))
    service.flush()
    service.close()
    assert sensitive not in caplog.text
    assert "shutdown failed" in caplog.text and "flush failed" in caplog.text
