import ipaddress
import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from netwatch.discovery.enrichment import VendorLookup, resolve_hostname
from netwatch.discovery.network import Lan
from netwatch.discovery.scanner import Scanner, ping_host, ping_sweep, read_neighbors
from netwatch.models.records import Observation
from netwatch.utils.config import Config
from netwatch.utils.process import DiscoveryError, run_command

LAN = Lan(ipaddress.IPv4Network("192.168.203.0/30"), "eth0")
OBS = Observation("192.168.203.2", "00:11:22:33:44:55")


def test_passive_scanner_does_not_probe_or_resolve(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("netwatch.discovery.scanner.detect_lan", Mock(return_value=LAN))
    neighbor = Mock(return_value=[OBS])
    monkeypatch.setattr("netwatch.discovery.scanner.read_neighbors", neighbor)
    scanner = Scanner(Config(vendor_file=tmp_path / "missing"))
    report = scanner.discover()
    assert report.complete and report.observations == (OBS,)
    neighbor.assert_called_once_with(LAN, None)


def test_scanner_enrichment_and_dedup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "vendors"
    path.write_text("001122 Example Devices\n")
    monkeypatch.setattr("netwatch.discovery.scanner.detect_lan", Mock(return_value=LAN))
    monkeypatch.setattr("netwatch.discovery.scanner.read_neighbors", Mock(return_value=[OBS, OBS]))
    monkeypatch.setattr("netwatch.discovery.scanner.resolve_hostname", Mock(return_value="nas"))
    report = Scanner(Config(vendor_file=path, resolve_hostnames=True)).discover()
    assert len(report.observations) == 1
    assert report.observations[0].vendor == "Example Devices"
    assert report.observations[0].hostname == "nas"


def test_ping_failure_is_degraded_but_keeps_passive_observations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("netwatch.discovery.scanner.detect_lan", Mock(return_value=LAN))
    monkeypatch.setattr(
        "netwatch.discovery.scanner.ping_sweep",
        Mock(side_effect=DiscoveryError("permission denied")),
    )
    monkeypatch.setattr("netwatch.discovery.scanner.read_neighbors", Mock(return_value=[OBS]))
    report = Scanner(
        Config(discovery_methods=("neighbor", "ping"), vendor_file=tmp_path / "missing")
    ).discover()
    assert not report.complete and report.observations == (OBS,)
    assert report.errors == ("permission denied",)


def test_neighbor_failure_does_not_crash(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("netwatch.discovery.scanner.detect_lan", Mock(return_value=LAN))
    monkeypatch.setattr(
        "netwatch.discovery.scanner.read_neighbors", Mock(side_effect=DiscoveryError("missing ip"))
    )
    report = Scanner(Config(vendor_file=tmp_path / "missing")).discover()
    assert not report.complete and not report.observations


def test_nmap_adapter_uses_only_validated_subnet(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("netwatch.discovery.scanner.detect_lan", Mock(return_value=LAN))
    command = Mock(
        return_value=(
            '<nmaprun><host><status state="up"/>'
            '<address addr="192.168.203.2" addrtype="ipv4"/></host>'
            '<runstats><finished exit="success"/></runstats></nmaprun>'
        )
    )
    monkeypatch.setattr("netwatch.discovery.scanner.run_command", command)
    neighbor = Mock(return_value=[OBS])
    monkeypatch.setattr("netwatch.discovery.scanner.read_neighbors", neighbor)
    report = Scanner(
        Config(discovery_methods=("nmap",), vendor_file=tmp_path / "missing")
    ).discover()
    arguments = command.call_args.args[0]
    assert arguments[-1] == "192.168.203.0/30" and "-sn" in arguments and "-n" in arguments
    assert arguments[arguments.index("--max-rate") + 1] == "10"
    neighbor.assert_called_once_with(LAN, {"192.168.203.2"})
    assert report.complete


def test_bad_nmap_payload_is_degraded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("netwatch.discovery.scanner.detect_lan", Mock(return_value=LAN))
    monkeypatch.setattr("netwatch.discovery.scanner.run_command", Mock(return_value="not XML"))
    monkeypatch.setattr("netwatch.discovery.scanner.read_neighbors", Mock(return_value=[]))
    report = Scanner(
        Config(discovery_methods=("nmap",), vendor_file=tmp_path / "missing")
    ).discover()
    assert not report.complete


def test_neighbor_cache_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps([{"dst": OBS.ip, "dev": "eth0", "lladdr": OBS.mac, "state": ["STALE"]}])
    command = Mock(return_value=payload)
    monkeypatch.setattr("netwatch.discovery.scanner.run_command", command)
    assert not read_neighbors(LAN, None)
    assert read_neighbors(LAN, {OBS.ip}) == [OBS]
    assert command.call_args.args[0][-1] == "eth0"


def test_scoped_neighbor_command_handles_real_iproute_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # iproute2 omits dev when `neigh show dev eth0` has already scoped the query.
    payload = json.dumps([{"dst": OBS.ip, "lladdr": OBS.mac, "state": ["REACHABLE"]}])
    command = Mock(return_value=payload)
    monkeypatch.setattr("netwatch.discovery.scanner.run_command", command)
    assert read_neighbors(LAN, None) == [OBS]
    command.assert_called_once_with(["ip", "-j", "-4", "neigh", "show", "dev", "eth0"])


def test_vendor_lookup_ieee_file_and_tab_separated_nmap(tmp_path: Path) -> None:
    path = tmp_path / "oui.txt"
    path.write_text(
        "00-11-22   (hex)\t\tExample Corporation\r\n"
        "001122     (base 16)\t\tExample Corporation\r\n"
        "\t\t\tUnrelated postal address\r\n"
        "001133\tTab Vendor\n"
    )
    vendors = VendorLookup(path)
    assert vendors.lookup(OBS.mac) == "Example Corporation"
    assert vendors.lookup("00:11:33:44:55:66") == "Tab Vendor"


def test_arp_fallback_requires_active_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "netwatch.discovery.scanner.run_command", Mock(side_effect=DiscoveryError("missing"))
    )
    with pytest.raises(DiscoveryError):
        read_neighbors(LAN, None)
    read = Mock(return_value=f"header\n{OBS.ip} 0x1 0x2 {OBS.mac} * eth0\n")
    monkeypatch.setattr(Path, "read_text", read)
    assert read_neighbors(LAN, {OBS.ip})[0].source == "arp"


def test_ping_sweep_targets_and_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    ping = Mock(side_effect=lambda ip, interface: ip == OBS.ip)
    delay = Mock()
    monkeypatch.setattr("netwatch.discovery.scanner.ping_host", ping)
    monkeypatch.setattr("netwatch.discovery.scanner.time.sleep", delay)
    assert ping_sweep(LAN, 2) == {OBS.ip}
    assert {call.args for call in ping.call_args_list} == {
        ("192.168.203.1", "eth0"),
        ("192.168.203.2", "eth0"),
    }
    assert delay.call_count == 2
    delay.assert_called_with(0.1)


@pytest.mark.parametrize("code,expected", [(0, True), (1, False)])
def test_ping_outcomes(monkeypatch: pytest.MonkeyPatch, code: int, expected: bool) -> None:
    process = Mock(return_value=subprocess.CompletedProcess([], code))
    monkeypatch.setattr(subprocess, "run", process)
    assert ping_host(OBS.ip, "eth0") is expected
    assert process.call_args.args[0] == ["ping", "-n", "-c", "1", "-W", "1", "-I", "eth0", OBS.ip]
    assert process.call_args.kwargs["timeout"] == 3


@pytest.mark.parametrize(
    "failure", [PermissionError(), FileNotFoundError(), subprocess.TimeoutExpired("ping", 3)]
)
def test_ping_process_failures(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=failure))
    with pytest.raises(DiscoveryError):
        ping_host(OBS.ip, "eth0")


def test_ping_permission_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 2)))
    with pytest.raises(DiscoveryError):
        ping_host(OBS.ip, "eth0")


def test_command_uses_argv_and_no_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    process = Mock(return_value=subprocess.CompletedProcess([], 0, stdout="[]"))
    monkeypatch.setattr(subprocess, "run", process)
    assert run_command(["ip", "-j", "address"]) == "[]"
    assert process.call_args.args[0] == ["ip", "-j", "address"]
    assert not process.call_args.kwargs.get("shell", False)
    assert process.call_args.kwargs["env"]["LC_ALL"] == "C"


@pytest.mark.parametrize(
    "failure",
    [PermissionError(), FileNotFoundError(), OSError(), subprocess.TimeoutExpired("ip", 10)],
)
def test_command_process_failures(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=failure))
    with pytest.raises(DiscoveryError):
        run_command(["ip"])


def test_nonzero_command_output_not_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 1, stdout="secret", stderr="secret")),
    )
    with pytest.raises(DiscoveryError, match="status 1") as error:
        run_command(["nmap"])
    assert "secret" not in str(error.value)


def test_offline_vendor_lookup_and_randomized_mac(tmp_path: Path) -> None:
    path = tmp_path / "vendors"
    path.write_text("# header\n001122 Example Inc\n021122 Unreliable\nBAD invalid\n001133    \n")
    lookup = VendorLookup(path)
    assert lookup.lookup(OBS.mac) == "Example Inc"
    assert lookup.lookup("02:11:22:33:44:55") is None
    assert lookup.lookup("00:aa:bb:cc:dd:ee") is None
    assert VendorLookup(tmp_path / "missing").lookup(OBS.mac) is None


def test_hostname_enrichment_failure_and_success(monkeypatch: pytest.MonkeyPatch) -> None:
    command = Mock(side_effect=[f"{OBS.ip} nas alias\n", DiscoveryError("no DNS"), "malformed"])
    monkeypatch.setattr("netwatch.discovery.enrichment.run_command", command)
    assert resolve_hostname(OBS.ip) == "nas"
    assert resolve_hostname(OBS.ip) is None
    assert resolve_hostname(OBS.ip) is None
    assert command.call_args.kwargs["timeout"] == 2
