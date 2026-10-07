from pathlib import Path
from unittest.mock import Mock

import pytest
from test_inventory import AT, OBS, result

from netwatch.cli.main import main
from netwatch.database.store import Store
from netwatch.services.inventory import Inventory
from netwatch.services.systemd import install_user_units
from netwatch.utils.config import Config
from netwatch.web.server import run_dashboard


def test_identification_never_changes_liveness_or_trust(store: Store) -> None:
    inventory = Inventory(store, 300)
    inventory.record(result(OBS), at=AT)
    store.set_offline(1)
    before = store.device("1")
    inventory.identify("1", hostname="local-nas", vendor="Local vendor")
    after = store.device("1")
    assert after.hostname == "local-nas" and after.vendor == "Local vendor"
    assert after.first_seen == before.first_seen and after.last_seen == before.last_seen
    assert not after.online and not after.trusted
    assert len(store.observations(1)) == 1
    count = len(store.events())
    inventory.identify("1", hostname="local-nas", vendor="Local vendor")
    assert len(store.events()) == count


@pytest.mark.parametrize(
    "values", [{"hostname": ""}, {"hostname": "a" * 254}, {"vendor": ""}, {"vendor": "a" * 501}]
)
def test_invalid_identification(store: Store, values: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        Inventory(store, 300).identify("1", **values)


@pytest.mark.parametrize(
    "answers,trusted",
    [(["", "", ""], False), (["NAS", "Storage", "trusted"], True), (["NAS", "", "unknown"], False)],
)
def test_interactive_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answers: list[str], trusted: bool
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("database_path: db.sqlite")
    with Store(tmp_path / "db.sqlite") as store:
        Inventory(store, 300).record(result(OBS), at=AT)
    monkeypatch.setattr("builtins.input", Mock(side_effect=answers))
    assert main(["--config", str(config), "review", "1"]) == 0
    with Store(tmp_path / "db.sqlite") as store:
        assert store.device("1").trusted == trusted
        assert store.device("1").name == (answers[0] or None)


def test_invalid_trust_review_is_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("database_path: db.sqlite")
    with Store(tmp_path / "db.sqlite") as store:
        Inventory(store, 300).record(result(OBS), at=AT)
    monkeypatch.setattr("builtins.input", Mock(side_effect=["NAS", "note", "yesplease"]))
    assert main(["--config", str(config), "review", "1"]) == 1
    with Store(tmp_path / "db.sqlite") as store:
        assert store.device("1").name is None and not store.device("1").trusted


def test_user_service_generation(tmp_path: Path) -> None:
    root = tmp_path / 'project with "quotes" %specifiers'
    executable = root / ".venv/bin/netwatch"
    executable.parent.mkdir(parents=True)
    executable.write_text("placeholder")
    config = root / "netwatch.yaml"
    config.write_text("database_path: db.sqlite")
    units = install_user_units(root, config, unit_dir=tmp_path / "units")
    for unit in units:
        contents = unit.read_text()
        assert "WantedBy=default.target" in contents and "Restart=on-failure" in contents
        assert "WorkingDirectory=/" in contents and 'WorkingDirectory="' not in contents
        assert "%%specifiers" in contents and '\\"quotes\\"' in contents
        assert unit.stat().st_mode & 0o777 == 0o600
    assert "web --port 8765" in units[1].read_text()


def test_user_service_requires_project_installation(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        install_user_units(tmp_path, tmp_path / "missing")


def test_active_ping_service_preserves_packaged_ping_file_capability(tmp_path: Path) -> None:
    executable = tmp_path / ".venv/bin/netwatch"
    executable.parent.mkdir(parents=True)
    executable.write_text("placeholder")
    config = tmp_path / "netwatch.yaml"
    config.write_text("discovery_methods: [neighbor, ping]")
    monitor, web = install_user_units(tmp_path, config, unit_dir=tmp_path / "units")
    # On hosts where ping_group_range disables ping sockets, packaged ping uses
    # cap_net_raw. User-manager seccomp filters imply NoNewPrivileges and block it.
    assert "NoNewPrivileges=false" in monitor.read_text()
    assert "RestrictAddressFamilies=" not in monitor.read_text()
    assert "NoNewPrivileges=true" in web.read_text()
    assert "RestrictAddressFamilies=" in web.read_text()


def test_web_server_loopback_and_graceful_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    server = Mock()
    server.run.side_effect = KeyboardInterrupt
    factory = Mock(return_value=server)
    monkeypatch.setattr("netwatch.web.server.create_server", factory)
    monkeypatch.setattr("netwatch.web.server.create_app", Mock())
    run_dashboard(Config(), 8765)
    assert factory.call_args.kwargs["host"] == "127.0.0.1"
    assert not factory.call_args.kwargs["expose_tracebacks"]
    server.close.assert_called_once()
    server.task_dispatcher.shutdown.assert_called_once_with(timeout=5)


def test_service_cli_honors_environment_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "custom.yaml"
    config.write_text("database_path: db.sqlite")
    monkeypatch.setenv("NETWATCH_CONFIG", str(config))
    installer = Mock(return_value=(tmp_path / "monitor.service", tmp_path / "web.service"))
    monkeypatch.setattr("netwatch.services.systemd.install_user_units", installer)
    assert main(["install-service"]) == 0
    assert installer.call_args.args[1] == config


def test_web_cli_and_review_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "netwatch.yaml"
    config.write_text("database_path: db.sqlite")
    with Store(tmp_path / "db.sqlite") as store:
        Inventory(store, 300).record(result(OBS), at=AT)
    web = Mock()
    monkeypatch.setattr("netwatch.web.server.run_dashboard", web)
    assert main(["--config", str(config), "web", "--port", "9000"]) == 0
    assert web.call_args.args[1] == 9000
    assert main(["--config", str(config), "--json", "web"]) == 1
    assert main(["--config", str(config), "--json", "review", "1"]) == 1
    assert main(["--config", str(config), "devices", "--review"]) == 0
    output = capsys.readouterr().out
    assert "FIRST SEEN" in output and "LAST SEEN" in output and "UNKNOWN" in output


@pytest.mark.parametrize("port", ["invalid", "80", "65536"])
def test_web_cli_invalid_port(port: str) -> None:
    with pytest.raises(SystemExit) as error:
        main(["web", "--port", port])
    assert error.value.code == 2
