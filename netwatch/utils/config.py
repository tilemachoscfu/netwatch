import math
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from netwatch.utils.validation import private_network, valid_interface


@dataclass(frozen=True)
class NotificationsConfig:
    console: bool = True
    telegram: bool = False
    security_cooldown: float = 3600
    long_absence: float = 86400

    def __post_init__(self) -> None:
        for key, minimum in (("security_cooldown", 3600), ("long_absence", 3600)):
            value = getattr(self, key)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < minimum
            ):
                raise ValueError(
                    f"notifications.{key} must be finite and at least {minimum} seconds"
                )


@dataclass(frozen=True)
class Config:
    subnet: str | None = None
    interface: str | None = None
    scan_interval: float = 60
    offline_timeout: float = 300
    database_path: Path = field(
        default_factory=lambda: (
            Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
            / "netwatch/netwatch.db"
        )
    )
    discovery_methods: tuple[str, ...] = ("neighbor",)
    max_hosts: int = 1024
    ping_workers: int = 8
    resolve_hostnames: bool = False
    vendor_file: Path | None = None
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    secrets_file: Path | None = None
    dhcp_files: tuple[Path, ...] = ()
    tailscale_url: str | None = None
    web_auth_required: bool = False

    def __post_init__(self) -> None:
        if self.subnet is not None:
            private_network(self.subnet)
        if self.interface is not None and not valid_interface(self.interface):
            raise ValueError("Invalid Linux interface name")
        for key, minimum in (("scan_interval", 10), ("offline_timeout", 10)):
            value = getattr(self, key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{key} must be numeric")
            if not math.isfinite(value) or value < minimum:
                raise ValueError(f"{key} must be finite and at least {minimum} seconds")
        if self.offline_timeout < self.scan_interval:
            raise ValueError("offline_timeout must be at least scan_interval")
        if (
            not isinstance(self.discovery_methods, (tuple, list))
            or not self.discovery_methods
            or any(method not in ("neighbor", "ping", "nmap") for method in self.discovery_methods)
            or len(set(self.discovery_methods)) != len(self.discovery_methods)
        ):
            raise ValueError(
                "discovery_methods must be a unique list of neighbor, ping, and/or nmap"
            )
        for key, maximum in (("max_hosts", 4096), ("ping_workers", 16)):
            value = getattr(self, key)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{key} must be an integer between 1 and {maximum}")
        if type(self.resolve_hostnames) is not bool:
            raise ValueError("resolve_hostnames must be true or false")
        if type(self.web_auth_required) is not bool:
            raise ValueError("web_auth_required must be true or false")
        if self.tailscale_url is not None:
            try:
                url = urlsplit(self.tailscale_url)
                valid = (
                    url.scheme == "https"
                    and bool(url.hostname)
                    and url.hostname.endswith(".ts.net")
                    and url.username is None
                    and url.password is None
                    and url.path in ("", "/")
                    and not url.query
                    and not url.fragment
                    and url.port in (None, 443, 8443, 10000)
                )
            except (TypeError, ValueError, AttributeError):
                valid = False
            if not valid:
                raise ValueError("tailscale_url must be an HTTPS ts.net root URL")


def _path(value: Any, base: Path, key: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a nonempty path string")
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def load_config(path: Path | None = None) -> Config:
    explicit = path is not None or "NETWATCH_CONFIG" in os.environ
    if path is None:
        path = Path(os.environ.get("NETWATCH_CONFIG", "netwatch.yaml"))
    if not path.exists() and not explicit:
        return _environment(Config())
    try:
        # Restrict file size before parsing arbitrary YAML.
        if path.stat().st_size > 65536:
            raise ValueError("Configuration exceeds 64 KiB")
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError("Cannot read YAML configuration") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict) or any(not isinstance(key, str) for key in data):
        raise ValueError("Configuration must be a YAML mapping")
    allowed = set(Config.__dataclass_fields__)
    if set(data) - allowed:
        raise ValueError("Unknown configuration keys: " + ", ".join(sorted(set(data) - allowed)))
    base = path.resolve().parent
    for key in ("database_path", "vendor_file", "secrets_file"):
        if key in data:
            data[key] = _path(data[key], base, key)
    if "dhcp_files" in data:
        if not isinstance(data["dhcp_files"], list):
            raise ValueError("dhcp_files must be a list of local paths")
        data["dhcp_files"] = tuple(_path(value, base, "dhcp_files") for value in data["dhcp_files"])
    if "discovery_methods" in data:
        if not isinstance(data["discovery_methods"], list):
            raise ValueError("discovery_methods must be a YAML list")
        data["discovery_methods"] = tuple(data["discovery_methods"])
    if "notifications" in data:
        notifications = data["notifications"]
        if not isinstance(notifications, dict) or set(notifications) - {
            "console",
            "telegram",
            "security_cooldown",
            "long_absence",
        }:
            raise ValueError("Invalid notification settings")
        for key, default in (("console", True), ("telegram", False)):
            if type(notifications.get(key, default)) is not bool:
                raise ValueError(f"notifications.{key} must be true or false")
        data["notifications"] = NotificationsConfig(**notifications)
    if "subnet" in data and data["subnet"] is not None and not isinstance(data["subnet"], str):
        raise ValueError("subnet must be a CIDR string or null")
    return _environment(Config(**data))


def _environment(config: Config) -> Config:
    secrets_override = os.environ.get("NETWATCH_SECRETS_FILE")
    if secrets_override is not None:
        config = replace(config, secrets_file=_path(secrets_override, Path.cwd(), "secrets_file"))
    override = os.environ.get("NETWATCH_DATABASE_PATH")
    if override is not None:
        return replace(config, database_path=_path(override, Path.cwd(), "NETWATCH_DATABASE_PATH"))
    return config
