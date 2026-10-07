"""Origin checks through the same proxy-header boundary used by Waitress."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from test_inventory import AT, OBS, result
from test_security import authorization
from waitress.proxy_headers import proxy_headers_middleware

from netwatch.database.store import Store
from netwatch.services.inventory import Inventory
from netwatch.utils.config import Config
from netwatch.web.app import create_app
from netwatch.web.auth import set_password
from netwatch.web.server import run_dashboard

EXTERNAL = "https://fixture-node.fixture-tailnet.ts.net:8443"
LOCAL = "http://localhost:8765"


@pytest.fixture(params=[EXTERNAL, LOCAL, "http://127.0.0.1:8765"])
def origin_client(tmp_path: Path, request: pytest.FixtureRequest):
    config = Config(
        database_path=tmp_path / "db.sqlite", tailscale_url=EXTERNAL, web_auth_required=True
    )
    with Store(config.database_path) as store:
        Inventory(store, 300).record(result(OBS), at=AT)
    password = "isolated-origin-test-password"
    set_password(config, password)
    app = create_app(config, secret_key="isolated-origin-session")
    app.config.update(TESTING=True)
    # Production strips all untrusted proxy headers before Flask sees them.
    app.wsgi_app = proxy_headers_middleware(app.wsgi_app, clear_untrusted=True)
    client = app.test_client()
    base = request.param
    auth = authorization(password)
    # TLS is terminated by Serve: the actual backend transport is HTTP/loopback.
    options = {
        "base_url": base,
        "environ_overrides": {
            "wsgi.url_scheme": "http",
            "SERVER_PORT": "8765",
            "REMOTE_ADDR": "127.0.0.1",
        },
    }
    response = client.get("/api/csrf", headers=auth, **options)
    assert response.status_code == 200
    assert ("Secure;" in response.headers["Set-Cookie"]) == (base == EXTERNAL)
    headers = {**auth, "X-CSRF-Token": response.json["csrf_token"], "Origin": base}
    return config, client, options, headers


def test_forms_preserve_same_origin_without_leaking_external_referrers(origin_client) -> None:
    _config, client, options, headers = origin_client
    page = client.get("/device/1", headers=headers, **options)
    # no-referrer makes browsers send Origin: null on a normal form POST.
    assert page.headers["Referrer-Policy"] == "same-origin"
    response = client.post(
        "/device/1",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "name": "Reviewed fixture",
            "notes": "Verified form",
            "trust": "known",
        },
        headers={key: value for key, value in headers.items() if key != "X-CSRF-Token"},
        **options,
    )
    assert response.status_code == 303
    assert response.headers["Location"] == "/device/1"
    device = client.get("/api/device/1", headers=headers, **options).json["device"]
    assert device["name"] == "Reviewed fixture" and device["trust_state"] == "KNOWN"


def test_authenticated_same_origin_api_update(origin_client) -> None:
    _config, client, options, headers = origin_client
    response = client.patch(
        "/api/device/1",
        json={"name": "Reviewed fixture", "trust_state": "KNOWN"},
        headers=headers,
        **options,
    )
    assert response.status_code == 200
    assert response.json["device"]["name"] == "Reviewed fixture"
    assert response.json["device"]["trust_state"] == "KNOWN"


@pytest.mark.parametrize(
    ("changes", "removed", "status"),
    [
        ({}, "Authorization", 401),
        ({}, "X-CSRF-Token", 403),
        ({"X-CSRF-Token": "invalid"}, None, 403),
        ({"Origin": "null"}, None, 403),
        ({"Origin": "https://evil.example"}, None, 403),
        ({"Origin": EXTERNAL + "/"}, None, 403),
        ({"Origin": EXTERNAL.replace(":8443", ":443")}, None, 403),
        ({"Host": "evil.example"}, None, 400),
        ({"Host": "evil.example", "X-Forwarded-Host": EXTERNAL[8:]}, None, 400),
        ({"Sec-Fetch-Site": "cross-site"}, None, 403),
        (
            {
                "Origin": "https://evil.example",
                "X-Forwarded-Host": "evil.example",
                "X-Forwarded-Proto": "https",
            },
            None,
            403,
        ),
    ],
)
def test_rejected_updates_do_not_mutate_inventory(origin_client, changes, removed, status) -> None:
    config, client, options, original = origin_client
    headers = {**original, **changes}
    if removed:
        headers.pop(removed)
    with Store(config.database_path) as store:
        before = store.device("1")
        events = store.events()
    response = client.patch(
        "/api/device/1",
        json={"name": "Must not save", "trust_state": "BLOCKED"},
        headers=headers,
        **options,
    )
    assert response.status_code == status
    with Store(config.database_path) as store:
        assert store.device("1") == before
        assert store.events() == events


def test_token_without_its_signed_session_is_rejected(origin_client) -> None:
    _config, client, options, headers = origin_client
    client = client.application.test_client()
    assert (
        client.patch(
            "/api/device/1", json={"name": "Must not save"}, headers=headers, **options
        ).status_code
        == 403
    )


@pytest.mark.parametrize("forwarded", [False, True])
def test_other_allowed_origin_cannot_update_this_host(origin_client, forwarded: bool) -> None:
    _config, client, options, headers = origin_client
    other = LOCAL if options["base_url"] == EXTERNAL else EXTERNAL
    headers = {**headers, "Origin": other, "Referer": other + "/device/1"}
    if forwarded:
        headers.update(
            {"X-Forwarded-Host": other.split("//")[1], "X-Forwarded-Proto": other.split(":")[0]}
        )
    assert (
        client.patch(
            "/api/device/1", json={"name": "Must not save"}, headers=headers, **options
        ).status_code
        == 403
    )


def test_forged_forwarded_proto_cannot_change_expected_scheme(origin_client) -> None:
    _config, client, options, headers = origin_client
    scheme, authority = options["base_url"].split("://")
    forged = "http" if scheme == "https" else "https"
    headers = {**headers, "Origin": f"{forged}://{authority}", "X-Forwarded-Proto": forged}
    assert (
        client.patch(
            "/api/device/1", json={"name": "Must not save"}, headers=headers, **options
        ).status_code
        == 403
    )


def test_external_authority_requires_loopback_even_with_forwarded_headers(origin_client) -> None:
    _config, client, options, headers = origin_client
    options = {
        **options,
        "base_url": EXTERNAL,
        "environ_overrides": {"REMOTE_ADDR": "192.168.203.5"},
    }
    headers = {
        **headers,
        "Origin": EXTERNAL,
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Host": EXTERNAL[8:],
        "X-Forwarded-Proto": "https",
    }
    assert (
        client.patch(
            "/api/device/1", json={"name": "Must not save"}, headers=headers, **options
        ).status_code
        == 403
    )


def test_saving_current_values_does_not_create_review_events(origin_client) -> None:
    config, client, options, headers = origin_client
    with Store(config.database_path) as store:
        before = store.device("1")
        events = store.events()
    assert (
        client.post(
            "/device/1",
            data={
                "name": before.name or "",
                "notes": before.notes,
                "trust": before.trust_state.lower(),
            },
            headers=headers,
            **options,
        ).status_code
        == 303
    )
    with Store(config.database_path) as store:
        assert store.device("1") == before
        assert store.events() == events


def test_server_keeps_proxy_headers_untrusted(monkeypatch: pytest.MonkeyPatch) -> None:
    create = Mock()
    monkeypatch.setattr("netwatch.web.server.create_app", Mock())
    monkeypatch.setattr("netwatch.web.server.create_server", create)
    run_dashboard(Config())
    assert create.call_args.kwargs["host"] == "127.0.0.1"
    assert create.call_args.kwargs["trusted_proxy"] is None
    assert create.call_args.kwargs["clear_untrusted_proxy_headers"] is True
