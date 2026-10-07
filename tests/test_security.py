import base64
import secrets
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_inventory import AT, OBS, result

from netwatch.cli.main import main, parser
from netwatch.database.store import Store
from netwatch.services.inventory import Inventory
from netwatch.utils.config import Config, load_config
from netwatch.web.app import create_app
from netwatch.web.auth import set_password


def authorization(password: str, username: str = "netwatch") -> dict[str, str]:
    value = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": "Basic " + value}


@pytest.fixture
def secured(tmp_path: Path):
    config = Config(database_path=tmp_path / "state/db.sqlite")
    with Store(config.database_path) as store:
        Inventory(store, 300).record(result(OBS), at=AT)
    password = secrets.token_urlsafe(24)
    set_password(config, password)
    app = create_app(config, secret_key="test-key")
    app.config.update(TESTING=True)
    return config, app.test_client(), password


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/security",
        "/devices",
        "/unknown",
        "/events",
        "/device/1",
        "/api/devices",
        "/api/summary",
        "/api/security",
        "/api/device/1",
        "/api/events",
        "/api/csrf",
        "/healthz",
    ],
)
def test_all_inventory_reads_require_authentication(secured, path: str) -> None:
    _config, client, password = secured
    response = client.get(path)
    assert response.status_code == 401 and response.headers["WWW-Authenticate"].startswith("Basic")
    assert OBS.mac.encode() not in response.data
    assert client.get(path, headers=authorization(password)).status_code == 200


def test_api_authorization_does_not_replace_csrf(secured) -> None:
    _config, client, password = secured
    assert client.patch("/api/device/1", json={"trusted": True}).status_code == 401
    auth = authorization(password)
    csrf = client.get("/api/csrf", headers=auth).json["csrf_token"]
    assert client.patch("/api/device/1", json={"trusted": True}, headers=auth).status_code == 403
    headers = {**auth, "X-CSRF-Token": csrf}
    assert (
        client.patch("/api/device/1", json={"name": "Reviewed NAS"}, headers=headers).status_code
        == 200
    )
    assert (
        client.patch(
            "/api/device/1",
            json={"trusted": True},
            headers={**headers, "Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    assert not client.get("/api/device/1", headers=auth).json["device"]["trusted"]


def test_failed_authentication_is_rate_limited_and_unicode_safe(secured) -> None:
    _config, client, _password = secured
    for _ in range(10):
        assert (
            client.get("/api/devices", headers=authorization("invalid", username="é")).status_code
            == 401
        )
    response = client.get("/api/devices", headers=authorization("invalid"))
    assert response.status_code == 429 and response.headers["Retry-After"] == "60"


def test_password_saved_as_private_hash_never_plaintext(secured) -> None:
    config, _client, password = secured
    path = config.database_path.with_suffix(".web-auth")
    assert path.stat().st_mode & 0o777 == 0o600
    assert password not in path.read_text() and path.read_text().startswith("scrypt:")
    path.chmod(0o644)
    with pytest.raises(ValueError):
        create_app(config)


def test_dangling_auth_symlink_cannot_disable_authentication(tmp_path: Path) -> None:
    config = Config(database_path=tmp_path / "db.sqlite")
    config.database_path.with_suffix(".web-auth").symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError):
        create_app(config)


def test_existing_session_key_must_not_be_world_readable(tmp_path: Path) -> None:
    config = Config(database_path=tmp_path / "db.sqlite")
    path = config.database_path.with_suffix(".web-key")
    path.write_text(secrets.token_hex(32))
    path.chmod(0o644)
    with pytest.raises(ValueError):
        create_app(config)


def test_required_authentication_fails_closed_without_hash(tmp_path: Path) -> None:
    config = Config(database_path=tmp_path / "db.sqlite", web_auth_required=True)
    with pytest.raises(ValueError, match="authentication is required"):
        create_app(config)


@pytest.mark.parametrize("kind", ["readable", "symlink"])
def test_existing_database_must_be_private_regular_file(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "db.sqlite"
    with Store(path):
        pass
    if kind == "readable":
        path.chmod(0o644)
    else:
        original = tmp_path / "original.sqlite"
        path.rename(original)
        path.symlink_to(original)
    with pytest.raises(ValueError):
        Store(path)


def test_xss_in_hostname_vendor_and_fingerprint_evidence_is_escaped(tmp_path: Path) -> None:
    config = Config(database_path=tmp_path / "db.sqlite")
    text = '<img src=x onerror="alert(1)">'
    with Store(config.database_path) as store:
        Inventory(store, 300).record(result(replace(OBS, hostname=text, vendor=text)), at=AT)
        Inventory(store, 300).edit("1", name="<script>alert(1)</script>", notes=text, set_name=True)
    client = create_app(config, secret_key="test-key").test_client()
    for path in ("/", "/device/1", "/events"):
        html = client.get(path).data
        assert b"<img src=x" not in html and b"<script>alert(1)" not in html
    assert b"&lt;img" in client.get("/device/1").data
    assert client.get("/api/device/1").headers["Content-Type"].startswith("application/json")


def test_tailscale_host_origin_secure_cookie_and_loopback_boundary(tmp_path: Path) -> None:
    external = "https://fixture-node.fixture-tailnet.ts.net:8443"
    config = Config(database_path=tmp_path / "db.sqlite", tailscale_url=external)
    with Store(config.database_path) as store:
        Inventory(store, 300).record(result(OBS), at=AT)
    client = create_app(config, secret_key="test-key").test_client()
    csrf = client.get("/api/csrf", base_url=external)
    assert "Secure;" in csrf.headers["Set-Cookie"]
    headers = {"X-CSRF-Token": csrf.json["csrf_token"], "Origin": external}
    assert (
        client.patch(
            "/api/device/1", json={"notes": "verified"}, base_url=external, headers=headers
        ).status_code
        == 200
    )
    assert (
        client.get(
            "/", base_url=external, environ_overrides={"REMOTE_ADDR": "192.168.203.5"}
        ).status_code
        == 403
    )
    assert (
        client.get("/", base_url="https://fixture-node.fixture-tailnet.ts.net:10000").status_code
        == 403
    )
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


@pytest.mark.parametrize(
    "url",
    [
        "http://fixture-node.fixture-tailnet.ts.net",
        "https://example.com",
        "https://user:private@fixture-node.fixture-tailnet.ts.net",
        "https://fixture-node.fixture-tailnet.ts.net/path",
        "https://fixture-node.fixture-tailnet.ts.net?x=1",
        "https://fixture-node.fixture-tailnet.ts.net:bad",
        "https://fixture-node.fixture-tailnet.ts.net:22",
        "https://fixture-node.fixture-tailnet.ts.net/#x",
        123,
    ],
)
def test_public_or_malformed_external_urls_rejected(url: object) -> None:
    with pytest.raises(ValueError):
        Config(tailscale_url=url)


def test_cli_cannot_bind_public_or_lan_address() -> None:
    with pytest.raises(SystemExit):
        parser().parse_args(["web", "--host", "0.0.0.0"])


def test_password_cli_and_cancel_never_echo_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("database_path: db.sqlite")
    password = secrets.token_urlsafe(24)
    monkeypatch.setattr("netwatch.cli.main.getpass.getpass", Mock(side_effect=[password, password]))
    assert main(["--config", str(path), "set-password"]) == 0
    assert password not in capsys.readouterr().out
    monkeypatch.setattr(
        "netwatch.cli.main.getpass.getpass", Mock(side_effect=[password, "different"])
    )
    assert main(["--config", str(path), "set-password"]) == 1
    assert password not in capsys.readouterr().err


def test_secret_config_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "secrets_file: local.secrets\ndhcp_files: [leases]\nnotifications: {telegram: true}"
    )
    config = load_config(path)
    assert config.secrets_file == tmp_path / "local.secrets" and config.notifications.telegram
    assert config.dhcp_files == (tmp_path / "leases",)
    monkeypatch.setenv("NETWATCH_SECRETS_FILE", str(tmp_path / "override.secrets"))
    assert load_config(path).secrets_file == tmp_path / "override.secrets"
