import ipaddress
from pathlib import Path
from unittest.mock import Mock

import pytest

from netwatch.discovery.network import Lan
from netwatch.discovery.scanner import Scanner, ping_sweep
from netwatch.models.records import Observation
from netwatch.utils.config import Config
from netwatch.utils.process import DiscoveryError


def test_ping_tool_failure_aborts_without_sweeping_subnet(monkeypatch: pytest.MonkeyPatch) -> None:
    ping = Mock(side_effect=DiscoveryError("permission denied"))
    monkeypatch.setattr("netwatch.discovery.scanner.ping_host", ping)
    monkeypatch.setattr("netwatch.discovery.scanner.time.sleep", Mock())
    lan = Lan(ipaddress.IPv4Network("192.168.203.0/24"), "eth0")
    with pytest.raises(DiscoveryError):
        ping_sweep(lan, 1)
    assert ping.call_count == 1


def test_hostname_budget_rotates_across_scans(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lan = Lan(ipaddress.IPv4Network("192.168.203.0/24"), "eth0")
    observations = [
        Observation("192.168.203.2", "00:11:22:33:44:55"),
        Observation("192.168.203.3", "00:11:22:33:44:66"),
    ]
    monkeypatch.setattr("netwatch.discovery.scanner.detect_lan", Mock(return_value=lan))
    monkeypatch.setattr(
        "netwatch.discovery.scanner.read_neighbors", Mock(return_value=observations)
    )
    monkeypatch.setattr(
        "netwatch.discovery.scanner.time.monotonic", Mock(side_effect=[0, 0, 11, 20, 20, 31])
    )
    resolve = Mock(side_effect=["first", "second"])
    monkeypatch.setattr("netwatch.discovery.scanner.resolve_hostname", resolve)
    scanner = Scanner(Config(resolve_hostnames=True, vendor_file=tmp_path / "missing"))
    first = scanner.discover()
    second = scanner.discover()
    assert first.observations[0].hostname == "first" and first.observations[1].hostname is None
    assert second.observations[0].hostname is None and second.observations[1].hostname == "second"
    assert first.complete and second.complete
