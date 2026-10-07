from pathlib import Path

import pytest

from netwatch.utils.config import Config, load_config
from netwatch.utils.validation import private_network


@pytest.mark.parametrize(
    "cidr",
    [
        "8.8.8.0/24",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "224.0.0.0/4",
        "192.0.2.0/24",
        "0.0.0.0/0",
        "fc00::/7",
        "192.168.203.1/24",
        "bad",
        "192.168.203.0/31",
        "192.168.0.0/15",
        "10.0.0.0/7",
    ],
)
def test_reject_non_lan_subnets(cidr: str) -> None:
    with pytest.raises(ValueError):
        private_network(cidr)


@pytest.mark.parametrize(
    "cidr", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "192.168.203.0/30"]
)
def test_accept_rfc1918_subnets(cidr: str) -> None:
    assert str(private_network(cidr)) == cidr


@pytest.mark.parametrize(
    "data",
    [
        "scan_interval: 1",
        "scan_interval: .nan",
        "scan_interval: .inf",
        "scan_interval: true",
        "scan_interval: '60'",
        "offline_timeout: 20",
        "discovery_methods: []",
        "discovery_methods: ping",
        "discovery_methods: [unknown]",
        "discovery_methods: [ping, ping]",
        "max_hosts: 5000",
        "max_hosts: true",
        "ping_workers: 17",
        "ping_workers: 0",
        "notifications: {console: yesplease}",
        "notifications: {webhook: secret}",
        "resolve_hostnames: 'false'",
        "unknown_key: 1",
        "[not, mapping]",
        "{1: value}",
        "subnet: 5",
        "interface: '-e'",
        "interface: 'eth0;id'",
        "database_path: ''",
        "vendor_file: null",
        "!!python/object/apply:os.system ['false']",
        "broken: [",
    ],
)
def test_reject_invalid_config(tmp_path: Path, data: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(data)
    with pytest.raises(ValueError):
        load_config(path)


def test_configuration_paths_and_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("database_path: data/db.sqlite\nvendor_file: oui.txt\ninterface: br-lan\n")
    config = load_config(path)
    assert config.database_path == tmp_path / "data/db.sqlite"
    assert config.vendor_file == tmp_path / "oui.txt"
    monkeypatch.setenv("NETWATCH_CONFIG", str(path))
    assert load_config().interface == "br-lan"
    monkeypatch.setenv("NETWATCH_DATABASE_PATH", str(tmp_path / "override.db"))
    assert load_config().database_path == tmp_path / "override.db"


def test_missing_defaults_and_explicit_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    assert load_config().discovery_methods == ("neighbor",)
    with pytest.raises(ValueError):
        load_config(tmp_path / "missing.yaml")
    monkeypatch.setenv("NETWATCH_CONFIG", str(tmp_path / "missing.yaml"))
    with pytest.raises(ValueError):
        load_config()


def test_configuration_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("#" * 65537)
    with pytest.raises(ValueError, match="64 KiB"):
        load_config(path)


def test_config_uses_safe_defaults() -> None:
    config = Config()
    assert config.scan_interval == 60 and config.offline_timeout == 300
    assert not config.resolve_hostnames and config.notifications.console
