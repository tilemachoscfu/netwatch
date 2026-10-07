import json
import logging
import queue
import re
import threading
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime
from typing import Any

from netwatch.notifications.alerts import Alert
from netwatch.notifications.console import clean_text
from netwatch.utils.config import Config
from netwatch.utils.secrets import load_secrets

logger = logging.getLogger(__name__)


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        # A redirect must never forward the token-bearing URL to another host.
        return None


def message(alert: Alert) -> str:
    if alert.kind in (
        "new_device",
        "blocked_device_online",
        "trusted_mac_changed",
        "known_identity_changed",
        "long_absence_return",
    ):
        title = alert.title if alert.priority != "INFO" else "⚠️ NEW DEVICE"
        device = alert.device
        first = datetime.fromisoformat(device.first_seen).strftime("%H:%M UTC")
        lines = [
            title,
            "",
            f"Device: {clean_text(device.name or device.hostname or 'Unknown')[:200]}",
            f"IP: {alert.details.get('ip', device.ip)}",
            f"MAC: {device.mac.upper()}",
            f"Vendor: {clean_text(device.vendor or 'Unknown')[:200]}",
            f"First seen: {first}",
            f"Status: {device.trust_state}",
        ]
        if alert.kind == "trusted_mac_changed":
            lines.append(f"Observed MAC: {clean_text(alert.details.get('new_mac', 'Unknown'))}")
            lines.append("Identity match is a candidate, not proof. No trust was transferred.")
        lines.extend(["", "Open Netwatch dashboard for review."])
        return "\n".join(lines)[:2000]
    titles = {
        "new_device": "⚠ NETWATCH — UNKNOWN DEVICE",
        "device_offline": "🔴 NETWATCH — DEVICE OFFLINE",
        "device_online": "🟢 NETWATCH — DEVICE ONLINE AGAIN",
        "ip_changed": "↔ NETWATCH — IP ADDRESS CHANGED",
    }
    device = alert.device
    lines = [
        titles[alert.kind],
        "",
        f"Name: {clean_text(device.name or device.hostname or 'Unknown')[:200]}",
        f"IP: {device.ip}",
        f"MAC: {device.mac}",
        f"Vendor: {clean_text(device.vendor or 'Unknown')[:500]}",
        f"First seen: {device.first_seen}",
        f"Time: {alert.occurred_at}",
    ]
    if alert.kind == "ip_changed":
        lines.append(f"Previous IP: {clean_text(alert.details.get('old', 'Unknown'))}")
    # Plain text avoids interpreting untrusted hostnames/names as Telegram markup.
    return "\n".join(lines)[:4000]


class TelegramProvider:
    """Bounded best-effort background delivery; network waits never delay scans."""

    security_only = True
    provider_key = "telegram"

    def __init__(self, token: str, chat_id: str) -> None:
        if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{20,}", token) or not re.fullmatch(
            r"-?[0-9]+|@[A-Za-z0-9_]{5,32}", chat_id
        ):
            raise ValueError("Invalid Telegram credentials")
        self._token = token
        self._chat_id = chat_id
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
        self._queue: queue.Queue[Alert] = queue.Queue(maxsize=128)
        self._stop = threading.Event()
        self._seen: deque[int] = deque(maxlen=4096)
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def send(self, alert: Alert) -> None:
        with self._lock:
            if self._stop.is_set() or alert.event_id in self._seen:
                return
            try:
                self._queue.put_nowait(alert)
            except queue.Full:
                logger.warning("Telegram queue full; event %d not queued", alert.event_id)
                return
            self._seen.append(alert.event_id)
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._work, name="netwatch-telegram", daemon=True
                )
                self._thread.start()

    def _work(self) -> None:
        while not self._stop.is_set():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._deliver(alert)
            except Exception:
                # Do not log exceptions: urllib diagnostics can contain the bot token.
                logger.warning("Telegram delivery failed for event %d", alert.event_id)
            finally:
                self._queue.task_done()

    def _deliver(self, alert: Alert) -> bool:
        body = json.dumps(
            {
                "chat_id": self._chat_id,
                "text": message(alert),
                "link_preview_options": {"is_disabled": True},
            }
        ).encode()
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{self._token}/sendMessage",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        for attempt in range(3):
            if self._stop.is_set():
                return False
            delay: float = 2**attempt
            try:
                with self._opener.open(request, timeout=5) as response:
                    payload = response.read(65537)
                    if len(payload) > 65536:
                        break
                    result = json.loads(payload)
                    if isinstance(result, dict) and result.get("ok") is True:
                        return True
                    # A successful HTTP response with an API rejection is not success.
                    break
            except urllib.error.HTTPError as error:
                try:
                    if error.code == 429:
                        try:
                            retry = json.loads(error.read(65536))["parameters"]["retry_after"]
                            if type(retry) is not int or not 1 <= retry <= 30:
                                break  # Never retry earlier than a long server rate limit.
                            delay = retry
                        except (ValueError, KeyError, TypeError):
                            break
                    elif not 500 <= error.code <= 599:
                        break
                finally:
                    error.close()
            except (OSError, urllib.error.URLError, ValueError):
                pass
            if attempt < 2 and self._stop.wait(delay):
                return False
        logger.warning("Telegram delivery exhausted for event %d", alert.event_id)
        return False

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)

    def flush(self) -> None:
        # One-shot CLI scans allow a bounded window for their queued alerts.
        with self._queue.all_tasks_done:
            self._queue.all_tasks_done.wait_for(
                lambda: self._queue.unfinished_tasks == 0, timeout=20
            )


def configured_telegram(config: Config) -> TelegramProvider | None:
    if not config.notifications.telegram:
        return None
    try:
        values = load_secrets(config.secrets_file)
        return TelegramProvider(
            values.get("NETWATCH_TELEGRAM_BOT_TOKEN", ""),
            values.get("NETWATCH_TELEGRAM_CHAT_ID", ""),
        )
    except ValueError:
        logger.warning(
            "Telegram disabled: credentials absent, invalid, or secrets file not private"
        )
        return None
