import io
import json
import secrets
import urllib.error
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_inventory import AT, OBS, result

from netwatch.database.store import Store
from netwatch.notifications.alerts import Alert
from netwatch.notifications.telegram import (
    NoRedirects,
    TelegramProvider,
    configured_telegram,
    message,
)
from netwatch.services.inventory import Inventory
from netwatch.services.monitor import Monitor
from netwatch.utils.config import Config, NotificationsConfig
from netwatch.utils.secrets import load_secrets, private_text


@pytest.fixture
def alert(store: Store) -> Alert:
    event = Inventory(store, 300).record(result(OBS), at=AT).events[0]
    return Alert(
        event.id, event.kind, "unknown", store.device("1"), event.occurred_at, event.details
    )


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> TelegramProvider:
    provider = TelegramProvider("123:" + secrets.token_urlsafe(32), "123")
    provider._opener = Mock()
    monkeypatch.setattr(provider._stop, "wait", Mock(return_value=False))
    monkeypatch.setattr("netwatch.notifications.telegram.threading.Thread", Mock())
    return provider


def response(payload: object = None) -> Mock:
    value = Mock()
    value.__enter__ = Mock(return_value=value)
    value.__exit__ = Mock()
    value.read.return_value = json.dumps(payload if payload is not None else {"ok": True}).encode()
    return value


def test_plain_text_format_and_timeout(provider: TelegramProvider, alert: Alert) -> None:
    provider._opener.open.return_value = response()
    assert provider._deliver(alert)
    request = provider._opener.open.call_args.args[0]
    body = json.loads(request.data)
    assert "NEW DEVICE" in body["text"] and "First seen:" in body["text"]
    assert body["chat_id"] == "123" and "parse_mode" not in body
    assert body["link_preview_options"]["is_disabled"]
    assert provider._opener.open.call_args.kwargs["timeout"] == 5
    assert request.full_url.startswith("https://api.telegram.org/bot")


def test_credentials_never_enter_inventory_or_dump(
    provider: TelegramProvider,
    store: Store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "netwatch.services.monitor.configured_telegram", Mock(return_value=provider)
    )
    scanner = Mock(discover=Mock(return_value=result(OBS)))
    Monitor(Config(), store, scanner, io.StringIO(), clock=lambda: AT).scan_once()
    assert provider._token not in "\n".join(store.connection.iterdump())
    assert provider._queue.qsize() == 1
    provider.close()


@pytest.mark.parametrize("kind", ["new_device", "device_offline", "device_online", "ip_changed"])
def test_all_messages(kind: str, alert: Alert) -> None:
    text = message(replace(alert, kind=kind, details={"old": "192.168.203.9"}))
    assert alert.device.mac.upper() in text or alert.device.mac in text
    assert alert.device.ip in text
    if kind == "ip_changed":
        assert "Previous IP: 192.168.203.9" in text


@pytest.mark.parametrize("failure", [TimeoutError(), urllib.error.URLError("unavailable")])
def test_retry_backoff(provider: TelegramProvider, alert: Alert, failure: Exception) -> None:
    provider._opener.open.side_effect = [failure, failure, response()]
    assert provider._deliver(alert)
    assert provider._opener.open.call_count == 3
    assert [call.args[0] for call in provider._stop.wait.call_args_list] == [1, 2]


@pytest.mark.parametrize(
    "status,retry,calls", [(401, None, 1), (500, None, 3), (429, 2, 3), (429, 99, 1)]
)
def test_api_failure_and_server_backoff(
    provider: TelegramProvider,
    alert: Alert,
    status: int,
    retry: int | None,
    calls: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    error = urllib.error.HTTPError(
        "https://api.telegram.org/bot" + provider._token,
        status,
        provider._token,
        {},
        io.BytesIO(json.dumps({"parameters": {"retry_after": retry}}).encode()),
    )
    provider._opener.open.side_effect = lambda *_a, **_k: urllib.error.HTTPError(
        error.url,
        status,
        error.reason,
        {},
        io.BytesIO(json.dumps({"parameters": {"retry_after": retry}}).encode()),
    )

    # Mock side effects must raise errors rather than return them.
    def fail(*_args: object, **_kwargs: object) -> None:
        raise urllib.error.HTTPError(
            error.url,
            status,
            error.reason,
            {},
            io.BytesIO(json.dumps({"parameters": {"retry_after": retry}}).encode()),
        )

    provider._opener.open.side_effect = fail
    assert not provider._deliver(alert)
    assert provider._opener.open.call_count == calls
    assert provider._token not in caplog.text and "https://api.telegram.org/bot" not in caplog.text


def test_http_rejection_closes_response(provider: TelegramProvider, alert: Alert) -> None:
    payload = io.BytesIO(b"{}")
    provider._opener.open.side_effect = urllib.error.HTTPError(
        "https://example.invalid", 401, "bad", {}, payload
    )
    assert not provider._deliver(alert)
    assert payload.closed


@pytest.mark.parametrize("payload", [{"ok": False}, [], "bad"])
def test_api_rejection_not_success(
    provider: TelegramProvider, alert: Alert, payload: object
) -> None:
    provider._opener.open.return_value = response(payload)
    assert not provider._deliver(alert)
    assert provider._opener.open.call_count == 1


def test_oversized_response_and_shutdown(provider: TelegramProvider, alert: Alert) -> None:
    value = response()
    value.read.return_value = b"x" * 65537
    provider._opener.open.return_value = value
    assert not provider._deliver(alert)
    provider.close()
    provider.send(alert)
    assert provider._queue.empty() and not provider._deliver(alert)


def test_queue_is_bounded_and_duplicate_event_not_requeued(
    provider: TelegramProvider, alert: Alert
) -> None:
    provider.send(alert)
    provider.send(alert)
    assert provider._queue.qsize() == 1
    for index in range(2, 131):
        provider.send(replace(alert, event_id=index))
    assert provider._queue.qsize() == 128
    provider._thread.start.assert_called_once()
    provider.close()
    provider._thread.join.assert_called_once_with(timeout=1)


def test_worker_isolates_failures_without_secret_diagnostics(
    provider: TelegramProvider,
    alert: Alert,
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider._queue.put(alert)

    def fail(_: Alert) -> None:
        provider._stop.set()
        raise RuntimeError(provider._token)

    provider._deliver = Mock(side_effect=fail)
    provider._work()
    provider.flush()
    assert provider._queue.unfinished_tasks == 0 and provider._token not in caplog.text


def test_redirect_refused() -> None:
    assert NoRedirects().redirect_request(None, None, None, None, None, None) is None


def test_secret_file_environment_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "local.secrets"
    token = "123:" + secrets.token_urlsafe(32)
    path.write_text(f"NETWATCH_TELEGRAM_BOT_TOKEN={token}\nNETWATCH_TELEGRAM_CHAT_ID=123\n")
    path.chmod(0o600)
    monkeypatch.setenv("NETWATCH_TELEGRAM_CHAT_ID", "456")
    assert load_secrets(path)["NETWATCH_TELEGRAM_CHAT_ID"] == "456"
    config = Config(secrets_file=path, notifications=NotificationsConfig(telegram=True))
    assert configured_telegram(config) is not None
    assert configured_telegram(Config()) is None
    path.chmod(0o644)
    assert configured_telegram(config) is None
    with pytest.raises(ValueError):
        private_text(path)


@pytest.mark.parametrize(
    "payload",
    [
        "TOKEN=private",
        "NETWATCH_TELEGRAM_CHAT_ID=",
        "NETWATCH_TELEGRAM_CHAT_ID=123\nNETWATCH_TELEGRAM_CHAT_ID=456",
    ],
)
def test_invalid_secrets_are_not_echoed(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "local.secrets"
    path.write_text(payload)
    path.chmod(0o600)
    with pytest.raises(ValueError) as error:
        load_secrets(path)
    assert payload not in str(error.value)


def test_secret_symlinks_size_and_ownership_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "private"
    path.write_text("x" * 16385)
    path.chmod(0o600)
    with pytest.raises(ValueError):
        private_text(path)
    path.write_text("private")
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        private_text(link)
    monkeypatch.setattr("netwatch.utils.secrets.os.geteuid", lambda: -1)
    with pytest.raises(ValueError):
        private_text(path)
