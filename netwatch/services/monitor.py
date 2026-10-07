import logging
import signal
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime
from typing import TextIO

from netwatch.database.store import Store
from netwatch.discovery.scanner import Scanner
from netwatch.models.records import ScanReport, timestamp, utc_now
from netwatch.notifications.alerts import ConsoleProvider, NotificationService
from netwatch.notifications.telegram import configured_telegram
from netwatch.services.fingerprints import FingerprintService
from netwatch.services.inventory import Inventory
from netwatch.utils.config import Config
from netwatch.utils.process import DiscoveryError

logger = logging.getLogger(__name__)


class Monitor:
    def __init__(
        self,
        config: Config,
        store: Store,
        scanner: Scanner,
        stream: TextIO,
        *,
        stop: threading.Event | None = None,
        clock: Callable[[], datetime] = utc_now,
        notifier: NotificationService | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.scanner = scanner
        self.stream = stream
        self.stop = stop or threading.Event()
        self.clock = clock
        self.inventory = Inventory(store, config.offline_timeout)
        providers = (ConsoleProvider(stream),) if config.notifications.console else ()
        telegram = configured_telegram(config) if notifier is None else None
        self.notifier = notifier or NotificationService(
            store,
            (*providers, telegram) if telegram is not None else providers,
            cooldown_seconds=config.notifications.security_cooldown,
            long_absence_seconds=config.notifications.long_absence,
        )

    def scan_once(self) -> ScanReport:
        started = self.clock()
        result = self.scanner.discover()
        report = self.inventory.record(result, at=self.clock(), started_at=started)
        try:
            FingerprintService(self.store, self.config).refresh(collect_topology=True)
        except (ValueError, OSError, sqlite3.Error):
            logger.warning("Fingerprint refresh unavailable; scan history preserved")
        self.notifier.dispatch(report.events)
        return report

    def run(self) -> None:
        previous_handlers = {}
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[sig] = signal.signal(sig, lambda *_: self.stop.set())
        try:
            # Reset last_success so a newly started but failing process cannot reuse old health.
            self.store.connection.execute("DELETE FROM monitor_status")
            self.store.heartbeat(timestamp(self.clock()), successful=False)
            while not self.stop.is_set():
                successful = False
                try:
                    report = self.scan_once()
                    successful = report.complete
                    logger.info(
                        "Scan %d: %d observed, %d events",
                        report.scan_id,
                        report.observed,
                        len(report.events),
                    )
                except (DiscoveryError, ValueError, OSError, sqlite3.Error):
                    logger.warning("Monitor scan failed; will retry", exc_info=True)
                    try:
                        at = timestamp(self.clock())
                        with self.store.transaction():
                            self.store.add_scan(
                                at,
                                at,
                                self.config.subnet,
                                self.config.interface,
                                False,
                                ("Scan failed; see logs",),
                            )
                    except sqlite3.Error:
                        logger.error("Could not persist failed scan", exc_info=True)
                try:
                    self.store.heartbeat(timestamp(self.clock()), successful=successful)
                except sqlite3.Error:
                    logger.error("Could not update monitor heartbeat", exc_info=True)
                # Delay after completion: slow scans never trigger back-to-back catch-up scans.
                self.stop.wait(self.config.scan_interval)
        finally:
            self.notifier.close()
            try:
                self.store.heartbeat(timestamp(self.clock()), successful=False, running=False)
            except sqlite3.Error:
                logger.error("Could not persist monitor shutdown", exc_info=True)
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)


def check_health(store: Store, config: Config, *, at: datetime | None = None) -> bool:
    status = store.monitor_status()
    if not status or not status["running"] or not status["last_success"]:
        return False
    at = at or utc_now()
    grace = max(config.scan_interval * 3, config.offline_timeout)
    try:
        heartbeat_age = (at - datetime.fromisoformat(status["heartbeat"])).total_seconds()
        success_age = (at - datetime.fromisoformat(status["last_success"])).total_seconds()
    except (ValueError, TypeError):
        return False
    return 0 <= heartbeat_age <= grace and 0 <= success_age <= grace
