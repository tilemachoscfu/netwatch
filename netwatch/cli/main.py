import argparse
import getpass
import json
import logging
import os
import sqlite3
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from netwatch import __version__
from netwatch.database.store import Store
from netwatch.discovery.scanner import Scanner
from netwatch.notifications.console import clean_text
from netwatch.services.inventory import Inventory
from netwatch.services.monitor import Monitor, check_health
from netwatch.utils.config import load_config
from netwatch.utils.locking import scan_lock
from netwatch.utils.process import DiscoveryError


def _limit(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("limit must be an integer") from exc
    if not 1 <= number <= 10000:
        raise argparse.ArgumentTypeError("limit must be between 1 and 10000")
    return number


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="netwatch", description="Private LAN device discovery and monitoring"
    )
    root.add_argument("--version", action="version", version=f"NetWatch {__version__}")
    root.add_argument("--config", type=Path, help="YAML configuration path")
    root.add_argument("--json", action="store_true", help="machine-readable JSON output")
    root.add_argument("--verbose", action="store_true", help="enable debug logging")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("scan", help="discover devices once")
    devices = commands.add_parser("devices", help="list device inventory")
    devices.add_argument("--online", action="store_true", help="show only online devices")
    devices.add_argument("--review", action="store_true", help="show identity and first/last seen")
    commands.add_parser("unknown", help="list devices awaiting review")
    events = commands.add_parser("events", help="show recent device events")
    events.add_argument("--device", help="device ID, MAC, IP, or assigned name")
    events.add_argument("--limit", type=_limit, default=50)
    trust = commands.add_parser("trust", help="mark a device trusted")
    trust.add_argument("device")
    trust.add_argument("--revoke", action="store_true", help="mark it unknown again")
    state = commands.add_parser("state", help="set an explicitly reviewed device state")
    state.add_argument("device")
    state.add_argument("state", choices=("TRUSTED", "KNOWN", "UNKNOWN", "BLOCKED"))
    info = commands.add_parser("info", help="show a device and recent history")
    info.add_argument("device")
    info.add_argument("--limit", type=_limit, default=20)
    edit = commands.add_parser("edit", help="set a device's name or notes")
    edit.add_argument("device")
    edit.add_argument("--name", help="assigned name; empty string clears it")
    edit.add_argument("--notes", help="notes; empty string clears them")
    review = commands.add_parser(
        "review", help="interactively review one device; blanks keep values"
    )
    review.add_argument("device")
    web = commands.add_parser("web", help="serve the local dashboard on 127.0.0.1")
    web.add_argument("--port", type=_limit_port, default=8765)
    commands.add_parser("monitor", help="scan continuously until interrupted")
    commands.add_parser("healthcheck", help="check monitor freshness without network operations")
    commands.add_parser("install-service", help="write user systemd units for this checkout")
    commands.add_parser("set-password", help="set an owner-only dashboard password hash")
    return root


def _limit_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1024 and 65535")
    return port


def _json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=True))


def _table(headers: tuple[str, ...], rows: list[tuple[object, ...]]) -> None:
    rendered = [tuple(clean_text(value)[:80] for value in row) for row in rows]
    widths = [
        max([len(header), *(len(row[index]) for row in rendered)])
        for index, header in enumerate(headers)
    ]
    print(
        "  ".join(
            header.ljust(width) for header, width in zip(headers, widths, strict=True)
        ).rstrip()
    )
    for row in rendered:
        print(
            "  ".join(value.ljust(width) for value, width in zip(row, widths, strict=True)).rstrip()
        )
    if not rows:
        print("(none)")


def _display_devices(
    store: Store, *, unknown: bool, online: bool, json_output: bool, review: bool = False
) -> None:
    devices = store.devices(unknown_only=unknown, online_only=online)
    if json_output:
        _json([asdict(device) for device in devices])
    elif review:
        _table(
            (
                "ID",
                "IP",
                "MAC",
                "HOSTNAME",
                "VENDOR",
                "FIRST SEEN",
                "LAST SEEN",
                "STATUS",
                "TRUST STATE",
                "USER NAME",
            ),
            [
                (
                    device.id,
                    device.ip,
                    device.mac,
                    device.hostname or "UNKNOWN",
                    device.vendor or "UNKNOWN",
                    device.first_seen,
                    device.last_seen,
                    "ONLINE" if device.online else "OFFLINE",
                    device.trust_state,
                    device.name or "UNKNOWN",
                )
                for device in devices
            ],
        )
    else:
        _table(
            ("ID", "IP", "MAC", "NAME / HOSTNAME", "VENDOR", "STATE", "TRUST"),
            [
                (
                    device.id,
                    device.ip,
                    device.mac,
                    device.name or device.hostname or "-",
                    device.vendor or "-",
                    "online" if device.online else "offline",
                    device.trust_state.lower(),
                )
                for device in devices
            ],
        )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if arguments.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        config = load_config(arguments.config)
        if arguments.command == "set-password":
            from netwatch.web.auth import set_password

            password = getpass.getpass("New dashboard password (minimum 12 characters): ")
            if password != getpass.getpass("Repeat dashboard password: "):
                raise ValueError("Passwords do not match; no changes saved")
            set_password(config, password)
            print("Password saved. Username: netwatch. Restart netwatch-web.service to apply.")
            return 0
        if arguments.command == "install-service":
            from netwatch.services.systemd import install_user_units

            config_path = arguments.config or Path(
                os.environ.get("NETWATCH_CONFIG", "netwatch.yaml")
            )
            paths = install_user_units(Path.cwd(), config_path)
            if arguments.json:
                _json({"units": [str(path) for path in paths]})
            else:
                for path in paths:
                    print(path)
                print("Run systemctl --user daemon-reload, then enable --now both units.")
            return 0
        if arguments.command == "web":
            if arguments.json:
                raise ValueError("web uses HTTP and logs; --json is for one-shot commands")
            from netwatch.web.server import run_dashboard

            run_dashboard(config, arguments.port)
            return 0
        if arguments.command == "healthcheck":
            with Store(config.database_path, readonly=True) as store:
                healthy = check_health(store, config)
            if arguments.json:
                _json({"healthy": healthy})
            else:
                print("healthy" if healthy else "unhealthy")
            return 0 if healthy else 1
        if arguments.command in ("scan", "monitor"):
            with scan_lock(config.database_path), Store(config.database_path) as store:
                monitor = Monitor(config, store, Scanner(config), sys.stderr)
                if arguments.command == "monitor":
                    if arguments.json:
                        raise ValueError(
                            "--json is supported for one-shot commands; monitor uses logs"
                        )
                    monitor.run()
                    return 0
                report = monitor.scan_once()
                monitor.notifier.flush()
                monitor.notifier.close()
                if arguments.json:
                    _json(asdict(report))
                else:
                    print(
                        f"Scan {report.scan_id}: {report.observed} observed, "
                        f"{len(report.new_devices)} new, {len(report.events)} events"
                        + (" (degraded)" if not report.complete else "")
                    )
                return 0 if report.complete else 1
        with Store(config.database_path) as store:
            inventory = Inventory(store, config.offline_timeout)
            if arguments.command in ("devices", "unknown"):
                _display_devices(
                    store,
                    unknown=arguments.command == "unknown",
                    online=getattr(arguments, "online", False),
                    json_output=arguments.json,
                    review=getattr(arguments, "review", False),
                )
            elif arguments.command == "events":
                device_id = store.device(arguments.device).id if arguments.device else None
                events = store.events(device_id, arguments.limit)
                if arguments.json:
                    _json([asdict(event) for event in events])
                else:
                    _table(
                        ("TIME (UTC)", "DEVICE", "EVENT", "DETAILS"),
                        [
                            (
                                event.occurred_at,
                                event.device_id,
                                event.kind,
                                json.dumps(event.details, ensure_ascii=True),
                            )
                            for event in events
                        ],
                    )
            elif arguments.command == "review":
                if arguments.json:
                    raise ValueError("review requires an interactive terminal")
                device = store.device(arguments.device)
                print(f"Device {device.id}: {device.ip} / {device.mac}")
                print("Blank answers keep current values. Use Ctrl+C to cancel without changes.")
                name = input(f"Name [{clean_text(device.name or 'UNKNOWN')}]: ").strip()
                notes = input(f"Notes [{clean_text(device.notes or '(none)')}]: ")
                trust = (
                    input("Trust [keep / trusted / known / unknown / blocked] (keep): ")
                    .strip()
                    .lower()
                )
                if trust not in ("", "keep", "trusted", "known", "unknown", "blocked"):
                    raise ValueError("Invalid review state; no changes saved")
                inventory.edit(
                    str(device.id),
                    name=name or device.name,
                    set_name=bool(name),
                    notes=notes or None,
                    trust_state=None if trust in ("", "keep") else trust.upper(),
                )
                print(f"Device {device.id}: review saved")
            elif arguments.command == "trust":
                inventory.edit(arguments.device, trusted=not arguments.revoke)
                device = store.device(arguments.device)
                if arguments.json:
                    _json(asdict(device))
                else:
                    print(f"Device {device.id}: {'trusted' if device.trusted else 'unknown'}")
            elif arguments.command == "state":
                inventory.edit(arguments.device, trust_state=arguments.state)
                device = store.device(arguments.device)
                if arguments.json:
                    _json(asdict(device))
                else:
                    print(f"Device {device.id}: {device.trust_state}")
            elif arguments.command == "edit":
                if arguments.name is None and arguments.notes is None:
                    raise ValueError("edit requires --name and/or --notes")
                device_id = str(store.device(arguments.device).id)
                inventory.edit(
                    device_id,
                    name=arguments.name or None,
                    notes=arguments.notes,
                    set_name=arguments.name is not None,
                )
                device = store.device(device_id)
                if arguments.json:
                    _json(asdict(device))
                else:
                    print(f"Device {device.id}: metadata updated")
            elif arguments.command == "info":
                device = store.device(arguments.device)
                events = store.events(device.id, arguments.limit)
                history = store.observations(device.id, arguments.limit)
                if arguments.json:
                    _json(
                        {
                            "device": asdict(device),
                            "events": [asdict(event) for event in events],
                            "observations": history,
                        }
                    )
                else:
                    for key, value in asdict(device).items():
                        print(f"{key}: {clean_text(value if value is not None else '-')}")
                    print(f"Recent events ({len(events)}):")
                    for event in events:
                        print(
                            f"  {event.occurred_at} {event.kind} "
                            f"{json.dumps(event.details, ensure_ascii=True)}"
                        )
                    print(f"Recent observations ({len(history)}):")
                    for observation in history:
                        print(
                            f"  {observation['observed_at']} {observation['ip']} "
                            f"{observation['source']}"
                        )
            if arguments.command in ("edit", "review", "trust"):
                from netwatch.services.fingerprints import FingerprintService

                FingerprintService(store, config).refresh()
        return 0
    except KeyboardInterrupt:
        return 130
    except (DiscoveryError, ValueError, OSError, sqlite3.Error, EOFError) as exc:
        if arguments.json:
            _json({"error": clean_text(exc)})
        else:
            print(f"netwatch: {clean_text(exc)}", file=sys.stderr)
        return 1
