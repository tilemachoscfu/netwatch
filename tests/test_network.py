import json
from unittest.mock import Mock

import pytest

from netwatch.discovery.network import detect_lan
from netwatch.utils.config import Config
from netwatch.utils.process import DiscoveryError


def addresses(*pairs: tuple[str, str]) -> str:
    return json.dumps(
        [
            {
                "ifname": name,
                "flags": ["UP"],
                "addr_info": [{"family": "inet", "local": ip, "prefixlen": 24}],
            }
            for name, ip in pairs
        ]
    )


def test_automatic_lan(monkeypatch: pytest.MonkeyPatch) -> None:
    command = Mock(return_value=addresses(("eth0", "192.168.203.10")))
    monkeypatch.setattr("netwatch.discovery.network.run_command", command)
    lan = detect_lan(Config())
    assert str(lan.network) == "192.168.203.0/24" and lan.interface == "eth0"
    command.assert_called_once_with(["ip", "-j", "-4", "address", "show"])


def test_choose_default_route_with_lowest_metric(monkeypatch: pytest.MonkeyPatch) -> None:
    command = Mock(
        side_effect=[
            addresses(("eth0", "192.168.203.10"), ("eth1", "10.0.0.10")),
            json.dumps([{"dev": "eth0", "metric": 100}, {"dev": "eth1", "metric": 200}]),
        ]
    )
    monkeypatch.setattr("netwatch.discovery.network.run_command", command)
    assert detect_lan(Config()).interface == "eth0"


def test_ambiguous_lan_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    command = Mock(side_effect=[addresses(("eth0", "192.168.203.10"), ("eth1", "10.0.0.10")), "[]"])
    monkeypatch.setattr("netwatch.discovery.network.run_command", command)
    with pytest.raises(DiscoveryError, match="Multiple"):
        detect_lan(Config())


def test_configured_subnet_must_be_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    command = Mock(return_value=addresses(("eth0", "192.168.203.10")))
    monkeypatch.setattr("netwatch.discovery.network.run_command", command)
    with pytest.raises(DiscoveryError, match="No connected"):
        detect_lan(Config(subnet="10.0.0.0/24"))
    with pytest.raises(DiscoveryError, match="No connected"):
        detect_lan(Config(subnet="192.168.0.0/16"))
    assert (
        str(detect_lan(Config(subnet="192.168.203.0/25", interface="eth0")).network)
        == "192.168.203.0/25"
    )


def test_active_scan_host_limit_precedes_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "netwatch.discovery.network.run_command",
        Mock(return_value=addresses(("eth0", "192.168.203.10"))),
    )
    with pytest.raises(DiscoveryError, match="max_hosts"):
        detect_lan(Config(discovery_methods=("ping",), max_hosts=10))
    assert detect_lan(Config(discovery_methods=("neighbor",), max_hosts=10)).interface == "eth0"


def test_hostile_or_public_interface_information_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "netwatch.discovery.network.run_command",
        Mock(return_value=addresses(("--script=x", "192.168.203.10"), ("eth1", "8.8.8.8"))),
    )
    with pytest.raises(DiscoveryError):
        detect_lan(Config())


@pytest.mark.parametrize("routes", ["invalid", "{}", '[{"dev":"eth0","metric":"bad"}]'])
def test_bad_routes_are_discovery_errors(monkeypatch: pytest.MonkeyPatch, routes: str) -> None:
    monkeypatch.setattr(
        "netwatch.discovery.network.run_command",
        Mock(side_effect=[addresses(("eth0", "192.168.203.10"), ("eth1", "10.0.0.10")), routes]),
    )
    with pytest.raises(DiscoveryError):
        detect_lan(Config())
