import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_inventory import OBS, result

from netwatch.cli.main import main
from netwatch.database.store import Store
from netwatch.models.records import timestamp, utc_now
from netwatch.notifications.console import clean_text
from netwatch.utils.locking import scan_lock
from netwatch.utils.process import DiscoveryError


@pytest.fixture
def cli_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("NETWATCH_DATABASE_PATH", raising=False)
    path = tmp_path / "config.yaml"
    path.write_text("database_path: inventory.db\n")
    monkeypatch.setattr(
        "netwatch.cli.main.Scanner",
        Mock(return_value=Mock(discover=Mock(return_value=result(OBS)))),
    )
    return path


def test_cli_inventory_workflow(cli_config: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = ["--config", str(cli_config)]
    assert main([*base, "--json", "scan"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["new_devices"][0]["mac"] == OBS.mac
    assert "NEW DEVICE DETECTED" in output.err
    assert main([*base, "--json", "unknown"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 1
    assert main([*base, "trust", "1"]) == 0
    assert "trusted" in capsys.readouterr().out
    assert main([*base, "edit", "1", "--name", "NAS", "--notes", "office"]) == 0
    capsys.readouterr()
    assert main([*base, "--json", "info", "NAS"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["device"]["trusted"] and info["device"]["notes"] == "office"
    assert len(info["observations"]) == 1
    assert main([*base, "--json", "unknown"]) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert main([*base, "--json", "events", "--device", "1", "--limit", "1"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 1
    assert main([*base, "--json", "devices", "--online"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 1


@pytest.mark.parametrize("command", [["devices"], ["unknown"], ["events"]])
def test_empty_tables(
    cli_config: Path, capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    assert main(["--config", str(cli_config), *command]) == 0
    assert "(none)" in capsys.readouterr().out


def test_cli_text_info_and_events(cli_config: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = ["--config", str(cli_config)]
    main([*base, "scan"])
    capsys.readouterr()
    assert main([*base, "info", "1"]) == 0
    assert "Recent observations (1)" in capsys.readouterr().out
    assert main([*base, "events"]) == 0
    assert "new_device" in capsys.readouterr().out


def test_cli_degraded_scan_exit(
    cli_config: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "netwatch.cli.main.Scanner",
        Mock(return_value=Mock(discover=Mock(return_value=result(OBS, complete=False)))),
    )
    assert main(["--config", str(cli_config), "scan"]) == 1
    assert "degraded" in capsys.readouterr().out


def test_cli_discovery_failure_is_concise(
    cli_config: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "netwatch.cli.main.Scanner",
        Mock(return_value=Mock(discover=Mock(side_effect=DiscoveryError("no LAN")))),
    )
    assert main(["--config", str(cli_config), "--json", "scan"]) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "no LAN"}


def test_missing_device_and_edit_arguments(
    cli_config: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--config", str(cli_config), "trust", "999"]) == 1
    assert "not found" in capsys.readouterr().err
    assert main(["--config", str(cli_config), "edit", "1"]) == 1
    assert "requires" in capsys.readouterr().err


def test_cli_healthcheck_is_readonly(cli_config: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--config", str(cli_config), "healthcheck"]) == 1
    capsys.readouterr()
    database = cli_config.parent / "inventory.db"
    assert not database.exists()
    with Store(database) as store:
        store.heartbeat(timestamp(utc_now()), successful=True)
    assert main(["--config", str(cli_config), "--json", "healthcheck"]) == 0
    assert json.loads(capsys.readouterr().out) == {"healthy": True}


def test_scan_lock_prevents_concurrent_scans(
    cli_config: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database = cli_config.parent / "inventory.db"
    with scan_lock(database):
        assert main(["--config", str(cli_config), "scan"]) == 1
        assert "Another scan" in capsys.readouterr().err
    assert main(["--config", str(cli_config), "scan"]) == 0


def test_terminal_escape_cleaning() -> None:
    assert "\x1b" not in clean_text("hello\x1b[31m\nworld")


def test_cli_monitor_dispatch(cli_config: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monitor = Mock()
    monkeypatch.setattr("netwatch.cli.main.Monitor", Mock(return_value=monitor))
    assert main(["--config", str(cli_config), "monitor"]) == 0
    monitor.run.assert_called_once()
    assert main(["--config", str(cli_config), "--json", "monitor"]) == 1


@pytest.mark.parametrize("state", ["TRUSTED", "KNOWN", "UNKNOWN", "BLOCKED"])
def test_cli_review_state(cli_config: Path, capsys: pytest.CaptureFixture[str], state: str) -> None:
    base = ["--config", str(cli_config)]
    assert main([*base, "scan"]) == 0
    capsys.readouterr()
    assert main([*base, "--json", "state", "1", state]) == 0
    device = json.loads(capsys.readouterr().out)
    assert device["trust_state"] == state and device["trusted"] == (state == "TRUSTED")
    assert main([*base, "devices", "--review"]) == 0
    assert state in capsys.readouterr().out


@pytest.mark.parametrize("limit", ["0", "10001", "bad"])
def test_bad_limit_arguments(limit: str) -> None:
    with pytest.raises(SystemExit) as error:
        main(["events", "--limit", limit])
    assert error.value.code == 2
